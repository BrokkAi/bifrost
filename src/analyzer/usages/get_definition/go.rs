use super::*;
use tree_sitter::Tree;

pub(super) fn parse_go_tree(source: &str) -> Option<Tree> {
    let mut parser = Parser::new();
    parser.set_language(&tree_sitter_go::LANGUAGE.into()).ok()?;
    parser.parse(source, None)
}

pub(super) fn resolve_go(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    source: &str,
    site: &ResolvedReferenceSite,
    graph: Option<&GoProjectGraph>,
) -> DefinitionLookupOutcome {
    let Some(go) = resolve_analyzer::<GoAnalyzer>(analyzer) else {
        return no_definition("go_analyzer_unavailable", "Go analyzer is unavailable");
    };
    let reference = site.text.as_str();
    if let Some(resolution) =
        graph.and_then(|graph| resolve_go_reference(graph, go, file, source, site))
    {
        let candidates = support.fqn_candidates(resolution.fqn_candidates);
        if !candidates.is_empty() {
            return candidates_outcome(candidates);
        }
        if resolution.shadowed {
            if let Some(outcome) =
                resolve_go_local_selector_chain(analyzer, support, file, source, site, reference)
            {
                return outcome;
            }
            return no_definition(
                "no_indexed_definition",
                format!("`{reference}` is shadowed by a local Go binding"),
            );
        }
        if let Some((_, name)) = reference.split_once('.')
            && let Some(package) = resolution.resolved_import_packages.first()
        {
            let candidates = go_package_member_candidates(support, package, name);
            if !candidates.is_empty() {
                return candidates_outcome(candidates);
            }
            if let Some(outcome) = go_package_selector_chain_outcome(support, package, site) {
                return outcome;
            }
            if !go_import_path_is_workspace(support, package) {
                return boundary(format!(
                    "`{package}` is outside this partial Go workspace analysis"
                ));
            }
            return no_definition(
                "no_indexed_definition",
                format!("`{name}` is not indexed in Go package `{package}`"),
            );
        }
        if let Some(package) = resolution
            .resolved_import_packages
            .iter()
            .find(|package| !go_import_path_is_workspace(support, package))
        {
            return boundary(format!(
                "`{package}` is outside this partial Go workspace analysis"
            ));
        }
    }

    let package = go_package_name(file, source);
    if let Some((qualifier, name)) = reference.split_once('.') {
        let imports = go_import_paths(go, file);
        if let Some(import_path) = imports.get(qualifier) {
            let candidates = go_package_member_candidates(support, import_path, name);
            if !candidates.is_empty() {
                return candidates_outcome(candidates);
            }
            if let Some(outcome) = go_package_selector_chain_outcome(support, import_path, site) {
                return outcome;
            }
            if !go_import_path_is_workspace(support, import_path) {
                return boundary(format!(
                    "`{import_path}` is outside this partial Go workspace analysis"
                ));
            }
            return no_definition(
                "no_indexed_definition",
                format!("`{name}` is not indexed in Go package `{import_path}`"),
            );
        }
        if let Some(outcome) =
            resolve_go_local_selector_chain(analyzer, support, file, source, site, reference)
        {
            return outcome;
        }
        let candidates = support.fqn_candidates([format!("{package}.{qualifier}.{name}")]);
        if !candidates.is_empty() {
            return candidates_outcome(candidates);
        }
        return no_definition(
            "no_indexed_definition",
            format!("`{reference}` did not resolve to an indexed Go definition"),
        );
    }

    let candidates = go_package_member_candidates(support, &package, reference);
    if !candidates.is_empty() {
        return candidates_outcome(candidates);
    }
    let same_file = support.file_identifier(file, reference);
    if !same_file.is_empty() {
        return candidates_outcome(same_file);
    }
    if let Some(import_path) = go_external_dot_import_path(go, support, file) {
        return boundary(format!(
            "`{import_path}` is outside this partial Go workspace analysis"
        ));
    }
    no_definition(
        "no_indexed_definition",
        format!("`{reference}` did not resolve to an indexed Go definition"),
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GoTypeLookupResolutionKind {
    Expression,
    InterfaceMethodOwner,
}

#[derive(Debug, Clone)]
pub(crate) struct GoTypeLookupResolution {
    pub(crate) fqn: String,
    pub(crate) kind: GoTypeLookupResolutionKind,
    pub(crate) member_name: Option<String>,
}

pub(crate) fn go_type_lookup_resolution(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    site: &ResolvedReferenceSite,
) -> Option<GoTypeLookupResolution> {
    let node = smallest_named_node_covering(root, site.focus_start_byte, site.focus_end_byte)?;
    if let Some((fqn, member_name)) =
        go_interface_method_owner_type_fqn(support, file, source, node)
    {
        return Some(GoTypeLookupResolution {
            fqn,
            kind: GoTypeLookupResolutionKind::InterfaceMethodOwner,
            member_name: Some(member_name),
        });
    }

    let expression = go_type_lookup_expression(node);
    let fqn = go_expression_type_fqn(
        analyzer,
        support,
        file,
        source,
        root,
        expression,
        site.range.start_byte,
    )?;
    Some(GoTypeLookupResolution {
        fqn,
        kind: GoTypeLookupResolutionKind::Expression,
        member_name: None,
    })
}

fn go_package_name(file: &ProjectFile, source: &str) -> String {
    let declared = source
        .lines()
        .find_map(|line| line.trim().strip_prefix("package "))
        .and_then(|rest| rest.split_whitespace().next())
        .unwrap_or("");
    crate::analyzer::go::packages::canonical_go_package_name(file, declared)
}

fn go_import_paths(
    go: &crate::analyzer::GoAnalyzer,
    file: &ProjectFile,
) -> HashMap<String, String> {
    let mut imports = HashMap::default();
    for import in go.import_info_of(file) {
        if matches!(import.alias.as_deref(), Some("_") | Some(".")) {
            continue;
        }
        let Some(import_path) = extract_go_import_path(&import.raw_snippet) else {
            continue;
        };
        let local = import
            .alias
            .as_deref()
            .map(default_go_import_local_name)
            .or_else(|| {
                import
                    .identifier
                    .as_deref()
                    .map(default_go_import_local_name)
            })
            .unwrap_or_else(|| default_go_import_local_name(&import_path));
        imports.insert(local, import_path);
    }
    imports
}

fn go_import_path_is_workspace(support: &DefinitionLookupIndex, import_path: &str) -> bool {
    support.fqn_prefix_exists(import_path)
}

fn go_package_member_candidates(
    support: &DefinitionLookupIndex,
    package: &str,
    name: &str,
) -> Vec<CodeUnit> {
    let mut candidates = support.fqn(&format!("{package}.{name}"));
    candidates.extend(support.fqn(&format!(
        "{package}.{}.{name}",
        crate::analyzer::GO_MODULE_SCOPE_SEGMENT
    )));
    sort_units(&mut candidates);
    candidates.dedup();
    candidates
}

fn go_package_selector_chain_outcome(
    support: &DefinitionLookupIndex,
    package: &str,
    site: &ResolvedReferenceSite,
) -> Option<DefinitionLookupOutcome> {
    let segments = dotted_reference_segments(site)?;
    let focus_index = dotted_focus_segment_index(site, &segments)?;
    if focus_index != 1 {
        return None;
    }
    let member = &segments.get(1)?.0;
    let candidates = go_package_member_candidates(support, package, member);
    (!candidates.is_empty()).then(|| candidates_outcome(candidates))
}

fn go_external_dot_import_path(
    go: &crate::analyzer::GoAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
) -> Option<String> {
    go.import_info_of(file).iter().find_map(|import| {
        (import.alias.as_deref() == Some("."))
            .then(|| extract_go_import_path(&import.raw_snippet))
            .flatten()
            .filter(|import_path| !go_import_path_is_workspace(support, import_path))
    })
}

fn resolve_go_local_selector_chain(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    source: &str,
    site: &ResolvedReferenceSite,
    reference: &str,
) -> Option<DefinitionLookupOutcome> {
    let segments: Vec<_> = reference.split('.').collect();
    if segments.len() < 2 {
        return None;
    }

    let tree = parse_go_tree(source)?;
    let root = tree.root_node();
    // Type the chain's base from its AST node, not the reference text. The text
    // reference expander drops non-identifier receivers (a `T{}` composite literal,
    // an `f()` call), yielding a base like `` in `.Name`, so `segments[0]` can't be
    // typed. `go_expression_type_fqn` types identifiers, composite literals, and
    // calls uniformly from the AST; fall back to the name lookup for a plain-ident
    // base the expander captured.
    let mut owner_fqn =
        go_selector_chain_base_node(root, site.focus_start_byte, site.focus_end_byte)
            .and_then(|base| {
                go_expression_type_fqn(
                    analyzer,
                    support,
                    file,
                    source,
                    root,
                    base,
                    site.focus_start_byte,
                )
            })
            .or_else(|| {
                go_binding_type_fqn(
                    analyzer,
                    support,
                    file,
                    source,
                    root,
                    segments[0],
                    site.focus_start_byte,
                )
            })?;
    let mut deepest_workspace_field = None;
    for (index, member) in segments[1..].iter().enumerate() {
        let lookup = go_indexed_field_lookup(analyzer, support, &owner_fqn, member);
        if let GoIndexedMemberLookup::Unique(candidate) = &lookup {
            deepest_workspace_field = Some(vec![candidate.clone()]);
        }
        if index == segments.len() - 2 {
            return match lookup {
                GoIndexedMemberLookup::Unique(candidate) => {
                    Some(candidates_outcome(vec![candidate]))
                }
                GoIndexedMemberLookup::Ambiguous => Some(go_ambiguous_selector_outcome(member)),
                GoIndexedMemberLookup::Missing => deepest_workspace_field
                    .map(|candidates| go_partial_selector_chain_outcome(candidates, member)),
            };
        }
        let Some(next_owner) = go_indexed_field_type_fqn(analyzer, support, &owner_fqn, member)
        else {
            return deepest_workspace_field
                .map(|candidates| go_partial_selector_chain_outcome(candidates, member));
        };
        owner_fqn = next_owner;
    }
    None
}

fn go_ambiguous_selector_outcome(member: &str) -> DefinitionLookupOutcome {
    ambiguous_definition(format!(
        "`{member}` resolves to multiple Go embedded members at the nearest promotion depth"
    ))
}

/// The base (leftmost operand) node of the selector chain covering the cursor —
/// e.g. `e{}` in `e{}.a.b`. Returns `None` when the cursor is not inside a
/// selector chain.
fn go_selector_chain_base_node(root: Node<'_>, start: usize, end: usize) -> Option<Node<'_>> {
    let mut top = smallest_named_node_covering(root, start, end)?;
    while let Some(parent) = top.parent() {
        if parent.kind() == "selector_expression" {
            top = parent;
        } else {
            break;
        }
    }
    if top.kind() != "selector_expression" {
        return None;
    }
    let mut base = top;
    while base.kind() == "selector_expression" {
        base = base
            .child_by_field_name("operand")
            .or_else(|| go_first_named_child(base))?;
    }
    Some(base)
}

fn go_partial_selector_chain_outcome(
    candidates: Vec<CodeUnit>,
    missing_member: &str,
) -> DefinitionLookupOutcome {
    let mut outcome = candidates_outcome(candidates);
    outcome.diagnostics.push(DefinitionLookupDiagnostic {
        kind: "partial_selector_chain".to_string(),
        message: format!(
            "resolved the deepest indexed Go workspace field before `{missing_member}`"
        ),
    });
    outcome
}

fn go_binding_type_fqn(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    name: &str,
    byte: usize,
) -> Option<String> {
    go_receiver_binding_type_fqn(analyzer, support, file, source, root, name, byte)
        .or_else(|| go_local_binding_type_fqn(analyzer, support, file, source, root, name, byte))
}

fn go_receiver_binding_type_fqn(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    name: &str,
    byte: usize,
) -> Option<String> {
    let mut current = smallest_named_node_covering(root, byte, byte)?;
    loop {
        if current.kind() == "method_declaration"
            && let Some(receiver) = current.child_by_field_name("receiver")
            && let Some(type_node) = go_parameter_type_for_name(receiver, source, name)
        {
            return go_resolve_type_fqn(analyzer, support, file, source, type_node);
        }
        current = current.parent()?;
    }
}

/// The type a local `name` is bound to, resolved by walking the parsed AST
/// outward from `byte`. Each enclosing scope is searched for the nearest
/// preceding `:=` or `var` declaration of `name`; the innermost match wins, so
/// shadowing is respected. An `if`/`for` initializer is a named child of the
/// statement node we walk through, so those bindings are covered too.
fn go_local_binding_type_fqn(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    name: &str,
    byte: usize,
) -> Option<String> {
    let mut scope = smallest_named_node_covering(root, byte, byte)?;
    loop {
        if let Some(binding) = go_nearest_binding_in_scope(scope, source, name, byte) {
            return match binding {
                GoLocalBinding::Type(type_node) => {
                    go_resolve_type_fqn(analyzer, support, file, source, type_node)
                }
                GoLocalBinding::Value(value_node) => {
                    go_value_type_fqn(analyzer, support, file, source, root, value_node, byte)
                }
                GoLocalBinding::RangeElement(range_node) => go_range_binding_type_fqn(
                    analyzer, support, file, source, root, range_node, byte,
                ),
            };
        }
        scope = scope.parent()?;
    }
}

/// How a local binding names its type: an explicit `var x T` annotation, or the
/// value expression of an inferred `x := value` binding to derive it from.
enum GoLocalBinding<'tree> {
    Type(Node<'tree>),
    Value(Node<'tree>),
    RangeElement(Node<'tree>),
}

fn go_nearest_binding_in_scope<'tree>(
    scope: Node<'tree>,
    source: &str,
    name: &str,
    byte: usize,
) -> Option<GoLocalBinding<'tree>> {
    let mut cursor = scope.walk();
    let mut nearest: Option<(usize, GoLocalBinding<'tree>)> = None;
    for child in scope.named_children(&mut cursor) {
        if child.end_byte() > byte {
            continue;
        }
        let binding = match child.kind() {
            "parameter_list" => go_parameter_list_binding(child, source, name),
            "short_var_declaration" => go_short_var_binding(child, source, name),
            "var_declaration" => go_var_declaration_binding(child, source, name),
            "range_clause" => go_range_binding(child, source, name),
            _ => None,
        };
        if let Some(binding) = binding
            && nearest
                .as_ref()
                .is_none_or(|(start, _)| child.start_byte() > *start)
        {
            nearest = Some((child.start_byte(), binding));
        }
    }
    nearest.map(|(_, binding)| binding)
}

fn go_parameter_list_binding<'tree>(
    node: Node<'tree>,
    source: &str,
    name: &str,
) -> Option<GoLocalBinding<'tree>> {
    let mut cursor = node.walk();
    for parameter in node.named_children(&mut cursor) {
        if parameter.kind() != "parameter_declaration" {
            continue;
        }
        let Some(type_node) = go_parameter_type_for_name(parameter, source, name) else {
            continue;
        };
        return Some(GoLocalBinding::Type(type_node));
    }
    None
}

fn go_range_binding<'tree>(
    node: Node<'tree>,
    source: &str,
    name: &str,
) -> Option<GoLocalBinding<'tree>> {
    let left = node.child_by_field_name("left")?;
    let index = go_expression_list_index(left, source, name)?;
    (index == 1).then_some(GoLocalBinding::RangeElement(node))
}

fn go_short_var_binding<'tree>(
    node: Node<'tree>,
    source: &str,
    name: &str,
) -> Option<GoLocalBinding<'tree>> {
    let left = node.child_by_field_name("left")?;
    let index = go_expression_list_index(left, source, name)?;
    let right = node.child_by_field_name("right")?;
    go_expression_list_item(right, index).map(GoLocalBinding::Value)
}

fn go_var_declaration_binding<'tree>(
    node: Node<'tree>,
    source: &str,
    name: &str,
) -> Option<GoLocalBinding<'tree>> {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        // `var x T` holds a `var_spec` directly; `var ( ... )` wraps each spec.
        let found = if child.kind() == "var_spec" {
            go_var_spec_binding(child, source, name)
        } else {
            let mut inner = child.walk();
            child
                .named_children(&mut inner)
                .filter(|spec| spec.kind() == "var_spec")
                .find_map(|spec| go_var_spec_binding(spec, source, name))
        };
        if found.is_some() {
            return found;
        }
    }
    None
}

fn go_var_spec_binding<'tree>(
    spec: Node<'tree>,
    source: &str,
    name: &str,
) -> Option<GoLocalBinding<'tree>> {
    let index = go_named_identifier_index(spec, source, name)?;
    if let Some(type_node) = spec.child_by_field_name("type") {
        return Some(GoLocalBinding::Type(type_node));
    }
    let value_list = spec.child_by_field_name("value")?;
    go_expression_list_item(value_list, index).map(GoLocalBinding::Value)
}

fn go_named_identifier_index(spec: Node<'_>, source: &str, name: &str) -> Option<usize> {
    let mut cursor = spec.walk();
    spec.named_children(&mut cursor)
        .filter(|child| child.kind() == "identifier")
        .position(|child| go_node_text(child, source).trim() == name)
}

fn go_expression_list_index(list: Node<'_>, source: &str, name: &str) -> Option<usize> {
    let mut cursor = list.walk();
    list.named_children(&mut cursor)
        .position(|child| go_node_text(child, source).trim() == name)
}

fn go_expression_list_item<'tree>(list: Node<'tree>, index: usize) -> Option<Node<'tree>> {
    if list.kind() == "expression_list" {
        let mut cursor = list.walk();
        list.named_children(&mut cursor).nth(index)
    } else {
        (index == 0).then_some(list)
    }
}

fn go_first_named_child(node: Node<'_>) -> Option<Node<'_>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor).next()
}

fn go_last_named_child(node: Node<'_>) -> Option<Node<'_>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor).last()
}

fn go_type_text_from_composite_value(value: &str) -> Option<&str> {
    let trimmed = value
        .trim_start_matches('&')
        .trim_start_matches('*')
        .trim_start();
    let end = trimmed.find(['{', '(']).unwrap_or(trimmed.len());
    let type_text = trimmed[..end].trim();
    (!type_text.is_empty()).then_some(type_text)
}

fn go_value_type_fqn(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    value_node: Node<'_>,
    byte: usize,
) -> Option<String> {
    if value_node.kind() == "call_expression"
        && let Some(fqn) = go_call_expression_return_type_fqn(
            analyzer, support, file, source, root, value_node, byte,
        )
    {
        return Some(fqn);
    }
    go_value_type_text(analyzer, support, file, source, root, value_node, byte)
        .and_then(|type_text| go_resolve_type_text_fqn(analyzer, support, file, source, &type_text))
}

fn go_value_type_text(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    value_node: Node<'_>,
    byte: usize,
) -> Option<String> {
    match value_node.kind() {
        "selector_expression" => go_selector_expression_type_text(
            analyzer, support, file, source, root, value_node, byte,
        ),
        "call_expression" => go_call_expression_return_type_text(
            analyzer, support, file, source, root, value_node, byte,
        ),
        "index_expression" => {
            go_index_expression_type_text(analyzer, support, file, source, root, value_node, byte)
        }
        "identifier" => {
            go_identifier_value_type_fqn(analyzer, support, file, source, root, value_node, byte)
                .and_then(|fqn| go_type_text_from_fqn(&fqn).map(str::to_string))
        }
        _ => {
            go_type_text_from_composite_value(go_node_text(value_node, source)).map(str::to_string)
        }
    }
}

fn go_identifier_value_type_fqn(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    value_node: Node<'_>,
    byte: usize,
) -> Option<String> {
    matches!(value_node.kind(), "identifier").then_some(())?;
    let identifier = go_node_text(value_node, source).trim();
    go_binding_type_fqn(
        analyzer,
        support,
        file,
        source,
        root,
        identifier,
        byte.min(value_node.start_byte()),
    )
}

fn go_selector_value_type_fqn(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    value_node: Node<'_>,
    byte: usize,
) -> Option<String> {
    if value_node.kind() != "selector_expression" {
        return None;
    }
    let qualifier_node = go_first_named_child(value_node)?;
    let field_node = go_last_named_child(value_node)?;
    let field = go_node_text(field_node, source).trim();
    let qualifier_type = go_expression_type_fqn(
        analyzer,
        support,
        file,
        source,
        root,
        qualifier_node,
        byte.min(value_node.start_byte()),
    )?;
    let (field_file, type_text) = go_indexed_field_type(analyzer, support, &qualifier_type, field)?;
    go_resolve_go_field_type_fqn(analyzer, support, &qualifier_type, &field_file, &type_text)
}

fn go_expression_type_fqn(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    expression: Node<'_>,
    byte: usize,
) -> Option<String> {
    match expression.kind() {
        "identifier" => go_binding_type_fqn(
            analyzer,
            support,
            file,
            source,
            root,
            go_node_text(expression, source).trim(),
            byte,
        ),
        "selector_expression" => {
            go_selector_value_type_fqn(analyzer, support, file, source, root, expression, byte)
        }
        "call_expression" | "composite_literal" | "index_expression" => {
            go_value_type_fqn(analyzer, support, file, source, root, expression, byte)
        }
        "parenthesized_expression" | "unary_expression" => {
            let mut cursor = expression.walk();
            expression.named_children(&mut cursor).find_map(|child| {
                go_expression_type_fqn(analyzer, support, file, source, root, child, byte)
            })
        }
        _ => None,
    }
}

fn go_type_lookup_expression(mut node: Node<'_>) -> Node<'_> {
    loop {
        let Some(parent) = node.parent() else {
            return node;
        };
        let node_id = node.id();
        let parent_is_semantic_expression = match parent.kind() {
            "selector_expression" => parent
                .child_by_field_name("field")
                .or_else(|| go_last_named_child(parent))
                .is_some_and(|field| field.id() == node_id),
            "call_expression" => parent
                .child_by_field_name("function")
                .is_some_and(|function| function.id() == node_id),
            "composite_literal" => parent
                .child_by_field_name("type")
                .is_some_and(|type_node| type_node.id() == node_id),
            "parenthesized_expression" | "unary_expression" => true,
            _ => false,
        };
        if !parent_is_semantic_expression {
            return node;
        }
        node = parent;
    }
}

fn go_interface_method_owner_type_fqn(
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    source: &str,
    mut node: Node<'_>,
) -> Option<(String, String)> {
    let selected = node;
    loop {
        if node.kind() == "method_elem" {
            let method_name = node
                .child_by_field_name("name")
                .or_else(|| go_first_named_child(node))?;
            if selected.start_byte() < method_name.start_byte()
                || selected.end_byte() > method_name.end_byte()
            {
                return None;
            }
            let interface = node
                .parent()
                .filter(|parent| parent.kind() == "interface_type")?;
            let type_spec = interface
                .parent()
                .filter(|parent| parent.kind() == "type_spec")?;
            let name = type_spec.child_by_field_name("name")?;
            let owner_fqn = go_resolve_type_name_in_package(
                support,
                &go_package_name(file, source),
                go_node_text(name, source),
            )?;
            return Some((owner_fqn, go_node_text(method_name, source).to_string()));
        }
        node = node.parent()?;
    }
}

fn go_range_binding_type_fqn(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    range_node: Node<'_>,
    byte: usize,
) -> Option<String> {
    let right = range_node
        .child_by_field_name("right")
        .or_else(|| go_last_named_child(range_node))?;
    let iterable_type =
        go_expression_type_text(analyzer, support, file, source, root, right, byte)?;
    let element_type = go_iterable_element_type_text(&iterable_type)?;
    go_resolve_type_text_fqn(analyzer, support, file, source, element_type)
}

fn go_expression_type_text(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    expression: Node<'_>,
    byte: usize,
) -> Option<String> {
    match expression.kind() {
        "identifier" => {
            let binding =
                go_nearest_visible_binding(root, source, go_node_text(expression, source), byte)?;
            match binding {
                GoLocalBinding::Type(type_node) => {
                    Some(go_node_text(type_node, source).to_string())
                }
                GoLocalBinding::Value(value_node) => {
                    go_value_type_text(analyzer, support, file, source, root, value_node, byte)
                }
                GoLocalBinding::RangeElement(range_node) => go_range_binding_type_fqn(
                    analyzer, support, file, source, root, range_node, byte,
                )
                .and_then(|fqn| go_type_text_from_fqn(&fqn).map(str::to_string)),
            }
        }
        "selector_expression" => go_selector_expression_type_text(
            analyzer, support, file, source, root, expression, byte,
        ),
        "index_expression" => {
            go_index_expression_type_text(analyzer, support, file, source, root, expression, byte)
        }
        _ => {
            go_type_text_from_composite_value(go_node_text(expression, source)).map(str::to_string)
        }
    }
}

fn go_selector_expression_type_text(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    expression: Node<'_>,
    byte: usize,
) -> Option<String> {
    let qualifier_node = go_first_named_child(expression)?;
    let field_node = go_last_named_child(expression)?;
    let field = go_node_text(field_node, source).trim();
    let qualifier_type = go_expression_type_fqn(
        analyzer,
        support,
        file,
        source,
        root,
        qualifier_node,
        byte.min(expression.start_byte()),
    )?;
    go_indexed_field_type(analyzer, support, &qualifier_type, field)
        .map(|(_, type_text)| type_text.trim().to_string())
}

fn go_index_expression_type_text(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    expression: Node<'_>,
    byte: usize,
) -> Option<String> {
    if expression.kind() != "index_expression" {
        return None;
    }
    let collection = expression.child_by_field_name("operand").or_else(|| {
        let mut cursor = expression.walk();
        expression.named_children(&mut cursor).next()
    })?;
    let iterable_type =
        go_expression_type_text(analyzer, support, file, source, root, collection, byte)?;
    go_iterable_element_type_text(&iterable_type).map(str::to_string)
}

fn go_call_expression_return_type_text(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    expression: Node<'_>,
    byte: usize,
) -> Option<String> {
    if expression.kind() != "call_expression" {
        return None;
    }
    let function = expression
        .child_by_field_name("function")
        .or_else(|| go_first_named_child(expression))?;
    match function.kind() {
        "selector_expression" => {
            let qualifier_node = go_first_named_child(function)?;
            let method_node = go_last_named_child(function)?;
            if qualifier_node.kind() == "identifier" {
                let qualifier = go_node_text(qualifier_node, source).trim();
                if let Some(import_path) =
                    go_import_paths(resolve_analyzer::<GoAnalyzer>(analyzer)?, file).get(qualifier)
                {
                    let function_name = go_node_text(method_node, source).trim();
                    if let Some(return_type) = go_callable_return_type_text(
                        analyzer,
                        go_package_member_candidates(support, import_path, function_name),
                    ) {
                        return Some(return_type);
                    }
                }
            }
            let owner_fqn = go_expression_type_fqn(
                analyzer,
                support,
                file,
                source,
                root,
                qualifier_node,
                byte.min(expression.start_byte()),
            )?;
            let method = go_node_text(method_node, source).trim();
            go_callable_return_type_text(analyzer, support.fqn(&format!("{owner_fqn}.{method}")))
        }
        "identifier" => {
            let package = go_package_name(file, source);
            let name = go_node_text(function, source).trim();
            go_callable_return_type_text(
                analyzer,
                go_package_member_candidates(support, &package, name),
            )
        }
        _ => None,
    }
}

fn go_call_expression_return_type_fqn(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    expression: Node<'_>,
    byte: usize,
) -> Option<String> {
    if expression.kind() != "call_expression" {
        return None;
    }
    let function = expression
        .child_by_field_name("function")
        .or_else(|| go_first_named_child(expression))?;
    match function.kind() {
        "selector_expression" => {
            let qualifier_node = go_first_named_child(function)?;
            let method_node = go_last_named_child(function)?;
            if qualifier_node.kind() == "identifier" {
                let qualifier = go_node_text(qualifier_node, source).trim();
                if let Some(import_path) =
                    go_import_paths(resolve_analyzer::<GoAnalyzer>(analyzer)?, file).get(qualifier)
                {
                    let function_name = go_node_text(method_node, source).trim();
                    let candidates =
                        go_package_member_candidates(support, import_path, function_name);
                    if let Some(fqn) = go_callable_return_type_fqn(analyzer, support, candidates) {
                        return Some(fqn);
                    }
                }
            }
            let owner_fqn = go_expression_type_fqn(
                analyzer,
                support,
                file,
                source,
                root,
                qualifier_node,
                byte.min(expression.start_byte()),
            )?;
            let method = go_node_text(method_node, source).trim();
            go_callable_return_type_fqn(
                analyzer,
                support,
                support.fqn(&format!("{owner_fqn}.{method}")),
            )
        }
        "identifier" => {
            let package = go_package_name(file, source);
            let name = go_node_text(function, source).trim();
            go_callable_return_type_fqn(
                analyzer,
                support,
                go_package_member_candidates(support, &package, name),
            )
        }
        _ => None,
    }
}

fn go_callable_return_type_text(
    analyzer: &dyn IAnalyzer,
    candidates: Vec<CodeUnit>,
) -> Option<String> {
    candidates.into_iter().find_map(|candidate| {
        for signature in analyzer.signatures(&candidate) {
            if let Some(return_type) = go_function_return_type_text(&signature) {
                return Some(return_type.to_string());
            }
        }
        candidate
            .signature()
            .and_then(go_function_return_type_text)
            .map(str::to_string)
    })
}

fn go_callable_return_type_fqn(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    candidates: Vec<CodeUnit>,
) -> Option<String> {
    candidates.into_iter().find_map(|candidate| {
        let signatures = analyzer.signatures(&candidate);
        let return_type = signatures
            .iter()
            .find_map(|signature| go_function_return_type_text(signature))
            .or_else(|| candidate.signature().and_then(go_function_return_type_text))?;
        let source = candidate.source().read_to_string().ok()?;
        go_resolve_type_text_fqn(analyzer, support, candidate.source(), &source, return_type)
    })
}

fn go_function_return_type_text(signature: &str) -> Option<&str> {
    let header = signature.split('{').next().unwrap_or(signature).trim();
    let rest = header.strip_prefix("func")?.trim_start();
    let rest = if rest.starts_with('(') {
        let receiver_end = go_matching_close_paren(rest, 0)?;
        rest.get(receiver_end + 1..)?.trim_start()
    } else {
        rest
    };
    let params_start = rest.find('(')?;
    let params_end = go_matching_close_paren(rest, params_start)?;
    let return_type = rest.get(params_end + 1..)?.trim();
    (!return_type.is_empty()).then_some(return_type)
}

fn go_matching_close_paren(text: &str, open_byte: usize) -> Option<usize> {
    let mut depth = 0usize;
    for (index, ch) in text
        .char_indices()
        .skip_while(|(index, _)| *index < open_byte)
    {
        match ch {
            '(' => depth += 1,
            ')' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some(index);
                }
            }
            _ => {}
        }
    }
    None
}

fn go_nearest_visible_binding<'tree>(
    root: Node<'tree>,
    source: &str,
    name: &str,
    byte: usize,
) -> Option<GoLocalBinding<'tree>> {
    let mut scope = smallest_named_node_covering(root, byte, byte)?;
    loop {
        if let Some(binding) = go_nearest_binding_in_scope(scope, source, name.trim(), byte) {
            return Some(binding);
        }
        scope = scope.parent()?;
    }
}

fn go_iterable_element_type_text(type_text: &str) -> Option<&str> {
    let trimmed = type_text.trim();
    trimmed
        .strip_prefix("[]")
        .or_else(|| {
            trimmed.strip_prefix("map[").and_then(|rest| {
                let close = rest.find(']')?;
                Some(rest[close + 1..].trim())
            })
        })
        .filter(|value| !value.is_empty())
}

fn go_type_text_from_fqn(fqn: &str) -> Option<&str> {
    fqn.rsplit_once('.').map(|(_, name)| name)
}

fn go_resolve_type_text_fqn(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    source: &str,
    type_text: &str,
) -> Option<String> {
    let (qualifier, name) = go_type_name_parts(type_text)?;
    if qualifier.is_some() {
        return go_resolve_qualified_type_from_file(analyzer, support, file, type_text);
    }
    go_resolve_type_name_in_package(support, &go_package_name(file, source), name)
}

fn go_parameter_type_for_name<'tree>(
    parameter_list: Node<'tree>,
    source: &str,
    name: &str,
) -> Option<Node<'tree>> {
    if parameter_list.kind() == "parameter_declaration" {
        return go_parameter_declaration_type_for_name(parameter_list, source, name);
    }
    let mut cursor = parameter_list.walk();
    for parameter in parameter_list.named_children(&mut cursor) {
        if parameter.kind() != "parameter_declaration" {
            continue;
        }
        let type_node = go_parameter_declaration_type_for_name(parameter, source, name);
        if type_node.is_some() {
            return type_node;
        }
    }
    None
}

fn go_parameter_declaration_type_for_name<'tree>(
    parameter: Node<'tree>,
    source: &str,
    name: &str,
) -> Option<Node<'tree>> {
    let mut names = Vec::new();
    let mut type_node = None;
    let mut inner = parameter.walk();
    for child in parameter.named_children(&mut inner) {
        match child.kind() {
            "identifier" => names.push(go_node_text(child, source)),
            _ => type_node = Some(child),
        }
    }
    names.contains(&name).then_some(type_node).flatten()
}

fn go_indexed_field_type_fqn(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    owner_fqn: &str,
    field: &str,
) -> Option<String> {
    let (field_file, type_text) = go_indexed_field_type(analyzer, support, owner_fqn, field)?;
    go_resolve_go_field_type_fqn(analyzer, support, owner_fqn, &field_file, &type_text)
}

fn go_indexed_field_type(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    owner_fqn: &str,
    field: &str,
) -> Option<(ProjectFile, String)> {
    match go_indexed_field_lookup(analyzer, support, owner_fqn, field) {
        GoIndexedMemberLookup::Unique(field_unit) => {
            go_field_unit_type_text(analyzer, &field_unit, field)
                .map(|type_text| (field_unit.source().clone(), type_text))
        }
        GoIndexedMemberLookup::Missing | GoIndexedMemberLookup::Ambiguous => None,
    }
}

fn go_indexed_field_lookup(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    owner_fqn: &str,
    field: &str,
) -> GoIndexedMemberLookup<CodeUnit> {
    let direct = |owner_fqn: &str, field: &str| support.fqn(&format!("{owner_fqn}.{field}"));
    let embedded = |owner_fqn: &str| go_embedded_field_types(analyzer, support, owner_fqn);
    go_unique_indexed_member_candidate_at_nearest_depth(owner_fqn, field, &direct, &embedded)
}

fn go_embedded_field_types(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    owner_fqn: &str,
) -> Vec<String> {
    support
        .fqn_direct_children(owner_fqn)
        .into_iter()
        .filter_map(|field| {
            let type_text = go_embedded_field_unit_type_text(analyzer, &field, None)?;
            go_resolve_go_field_type_fqn(analyzer, support, owner_fqn, field.source(), &type_text)
        })
        .collect()
}

fn go_field_unit_type_text(
    analyzer: &dyn IAnalyzer,
    field_unit: &CodeUnit,
    field: &str,
) -> Option<String> {
    let signature = field_unit
        .signature()
        .map(str::to_string)
        .or_else(|| analyzer.signatures(field_unit).first().cloned())?;
    let trimmed = signature.trim();
    if let Some(type_text) = trimmed
        .strip_prefix(field)
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        return Some(type_text.to_string());
    }
    let simple = go_simple_type_name(trimmed)?;
    (simple == field).then(|| trimmed.to_string())
}

fn go_resolve_go_field_type_fqn(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    owner_fqn: &str,
    field_file: &ProjectFile,
    type_text: &str,
) -> Option<String> {
    if let Some(fqn) = go_resolve_qualified_type_from_file(analyzer, support, field_file, type_text)
    {
        return Some(fqn);
    }
    let package = owner_fqn.rsplit_once('.').map(|(package, _)| package)?;
    go_resolve_type_name_in_package(support, package, type_text)
}

fn go_resolve_qualified_type_from_file(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    type_text: &str,
) -> Option<String> {
    let (Some(qualifier), name) = go_type_name_parts(type_text)? else {
        return None;
    };
    let go = resolve_analyzer::<GoAnalyzer>(analyzer)?;
    let import_path = go_import_paths(go, file).remove(qualifier)?;
    let fqn = format!("{import_path}.{name}");
    support.fqn_exists(&fqn).then_some(fqn)
}

fn go_resolve_type_fqn(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    source: &str,
    type_node: Node<'_>,
) -> Option<String> {
    let type_text = go_node_text(type_node, source);
    go_resolve_qualified_type_from_file(analyzer, support, file, type_text).or_else(|| {
        go_resolve_type_name_in_package(support, &go_package_name(file, source), type_text)
    })
}

fn go_resolve_type_name_in_package(
    support: &DefinitionLookupIndex,
    package: &str,
    type_text: &str,
) -> Option<String> {
    let name = go_simple_type_name(type_text)?;
    let fqn = format!("{package}.{name}");
    support.fqn_exists(&fqn).then_some(fqn)
}

fn go_node_text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    source
        .get(node.start_byte()..node.end_byte())
        .unwrap_or_default()
        .trim()
}
