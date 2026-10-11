// Closed JavaScript/TypeScript declaration and lexical-scope relations used
// by the CodeQL parity adapter.
//
// The relations below select syntax from tree-sitter first. Source text is
// consulted only for the value of an already-selected identifier or string
// literal; it is never used to locate syntax. Variable scope identity comes
// from the shared JS/TS lexical binding index; function-declaration scope is
// the AST node (or synthesized file root) that owns the declaration, so equal
// spellings in different functions and files do not join.

use crate::analyzer::common::language_for_file;
use crate::analyzer::usages::get_definition::parse_tree_for_language;
use crate::analyzer::{
    IAnalyzer, JsTsLexicalBindingIndex, JsTsLexicalBindingScope, Language, ProjectFile, Range,
    static_member_property, static_property_name, ts_object_literal_property_name,
};
use crate::query::JsRule;
use strsim::damerau_levenshtein;
use std::collections::HashMap;
use tree_sitter::{Node, Tree};

use super::language_rules::LanguageRuleMatches;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
enum ScopeKind {
    File,
    Function,
    Block,
    Loop,
    Catch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
struct ScopeId {
    start_byte: usize,
    end_byte: usize,
    kind: ScopeKind,
}

/// Return the exact structural spans selected by one closed JavaScript or
/// TypeScript relation.
pub(super) fn matches_for_file(
    _analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    rule: JsRule,
) -> LanguageRuleMatches {
    let language = language_for_file(file);
    if !matches!(language, Language::JavaScript | Language::TypeScript) {
        return LanguageRuleMatches::default();
    }
    let Some(tree) = parse_tree_for_language(file, language, source) else {
        return LanguageRuleMatches::default();
    };
    let root = tree.root_node();
    let lexical = JsTsLexicalBindingIndex::build(root, source);
    let mut ranges = match rule {
        JsRule::FunctionDeclarationConflict => function_declaration_conflicts(root, source),
        JsRule::VariableRedeclaration => variable_redeclarations(root, source, &lexical),
        JsRule::VariableInitializationConflict => variable_initialization_conflicts(root, source),
        JsRule::MissingVariableDeclaration => missing_variable_declarations(root, source, &lexical),
        JsRule::NestedFunctionReferenceInDefaultParameter => {
            nested_function_references_in_defaults(root, source)
        }
        JsRule::MissingThisQualifier => missing_this_qualifiers(&tree, source),
        JsRule::MixedStaticInstanceThisAccess => {
            mixed_static_instance_this_accesses(&tree, source)
        }
        JsRule::OverwrittenProperty => overwritten_properties(&tree, source),
        JsRule::MisspelledIdentifier => misspelled_identifiers(&tree, source),
    };
    ranges.sort_unstable();
    ranges.dedup();
    if rule == JsRule::MissingVariableDeclaration {
        let dynamic_scopes = dynamic_scope_ranges(root, source);
        if !dynamic_scopes.is_empty() {
            let scope_details = dynamic_scopes
                .iter()
                .map(|scope| format!("{} {:?}", scope.kind, scope.range))
                .collect::<Vec<_>>();
            return LanguageRuleMatches::incomplete(
                ranges,
                language.config_label(),
                format!(
                    "{} missing-variable-declaration is incomplete for {}: dynamic scope prevents exhaustive binding and liveness resolution at {scope_details:?}",
                    language.config_label(),
                    file.rel_path().display(),
                ),
            );
        }
    }
    LanguageRuleMatches::from_ranges(ranges)
}

fn function_declaration_conflicts(root: Node<'_>, source: &str) -> Vec<Range> {
    let mut groups: HashMap<(ScopeId, String), Vec<Node<'_>>> = HashMap::new();
    for function in descendants(root) {
        if !is_function_declaration(function) || !has_function_body(function) {
            continue;
        }
        let Some(name) = function.child_by_field_name("name") else {
            continue;
        };
        let scope = function_declaration_scope(function, root, source);
        if scope.kind == ScopeKind::File && !is_module(root) {
            continue;
        }
        groups
            .entry((scope, node_text(source, name).to_owned()))
            .or_default()
            .push(name);
    }
    groups
        .into_values()
        .filter(|names| names.len() > 1)
        .flat_map(|mut names| {
            names.sort_by_key(|name| name.start_byte());
            let keep = names.len().saturating_sub(1);
            names
                .into_iter()
                .take(keep)
                .map(node_range)
                .collect::<Vec<_>>()
        })
        .collect()
}

fn variable_redeclarations(
    root: Node<'_>,
    source: &str,
    lexical: &JsTsLexicalBindingIndex,
) -> Vec<Range> {
    let declarations = var_declarations(root);
    let mut groups: HashMap<String, Vec<(JsTsLexicalBindingScope, Vec<Node<'_>>)>> =
        HashMap::new();
    for declaration in declarations {
        let name = node_text(source, declaration).to_owned();
        let Some(scope) = lexical.binding_scope_at(&name, declaration.start_byte()) else {
            continue;
        };
        let scopes = groups.entry(name).or_default();
        if let Some((_, declarations)) = scopes.iter_mut().find(|(candidate, _)| *candidate == scope)
        {
            declarations.push(declaration);
        } else {
            scopes.push((scope, vec![declaration]));
        }
    }
    groups
        .into_values()
        .flat_map(|scopes| {
            scopes
                .into_iter()
                .filter(|(_, names)| names.len() > 1)
                .flat_map(|(_, mut names)| {
                    names.sort_by_key(|name| name.start_byte());
                    names.into_iter().skip(1).map(node_range).collect::<Vec<_>>()
                })
        })
        .collect()
}

fn variable_initialization_conflicts(root: Node<'_>, source: &str) -> Vec<Range> {
    let mut ranges = Vec::new();
    for declaration in descendants(root) {
        if !is_variable_declaration(declaration) {
            continue;
        }
        let declarators = named_children(declaration)
            .into_iter()
            .filter(|child| child.kind() == "variable_declarator")
            .collect::<Vec<_>>();
        for (first_index, first) in declarators.iter().enumerate() {
            if first.child_by_field_name("value").is_none() {
                continue;
            }
            let first_names = binding_identifiers(first.child_by_field_name("name"));
            for second in declarators.iter().skip(first_index + 1) {
                let Some(second_initializer) = second.child_by_field_name("value") else {
                    continue;
                };
                let second_names = binding_identifiers(second.child_by_field_name("name"));
                let shared_names = first_names.iter().filter(|first_name| {
                    second_names.iter().any(|second_name| {
                        node_text(source, **first_name) == node_text(source, *second_name)
                    })
                });
                for name in shared_names {
                    if !initializer_references_name(second_initializer, source, node_text(source, *name))
                    {
                        ranges.push(node_range(*second));
                        break;
                    }
                }
            }
        }
    }
    ranges
}

fn missing_variable_declarations(
    root: Node<'_>,
    source: &str,
    lexical: &JsTsLexicalBindingIndex,
) -> Vec<Range> {
    if has_dynamic_scope(root, source) {
        return Vec::new();
    }
    let mut ranges = Vec::new();
    for function in descendants(root)
        .into_iter()
        .filter(|node| is_function_node(node.kind()))
    {
        let mut accesses = descendants(function)
            .into_iter()
            .filter(|node| enclosing_function(*node).is_some_and(|owner| owner.id() == function.id()))
            .filter(|node| is_identifier_reference(*node))
            .map(|node| Access {
                name: node_text(source, node).to_owned(),
                node,
                write: is_simple_assignment_target(node),
            })
            .collect::<Vec<_>>();
        accesses.sort_by_key(|access| access.node.start_byte());

        let mut first_by_name: HashMap<String, Access<'_>> = HashMap::new();
        for access in &accesses {
            first_by_name
                .entry(access.name.clone())
                .or_insert_with(|| access.clone());
        }
        for (name, first) in first_by_name {
            if !first.write
                || !accesses_name_is_read_after(
                    function,
                    source,
                    &name,
                    first.node.start_byte(),
                )
                || lexical.is_bound_at(&name, first.node.start_byte())
            {
                continue;
            }
            ranges.push(node_range(first.node));
        }
    }
    ranges
}

#[derive(Debug, Clone)]
struct Access<'tree> {
    name: String,
    node: Node<'tree>,
    write: bool,
}

fn accesses_name_is_read_after(
    function: Node<'_>,
    source: &str,
    name: &str,
    first_byte: usize,
) -> bool {
    descendants(function).into_iter().any(|node| {
        node.start_byte() > first_byte
            && enclosing_function(node).is_some_and(|owner| owner.id() == function.id())
            && is_identifier_reference(node)
            && node_text(source, node) == name
            && !is_simple_assignment_target(node)
    })
}

fn nested_function_references_in_defaults(root: Node<'_>, source: &str) -> Vec<Range> {
    let mut ranges = Vec::new();
    for outer in descendants(root)
        .into_iter()
        .filter(|node| is_function_node(node.kind()))
    {
        let Some(parameters) = outer.child_by_field_name("parameters") else {
            continue;
        };
        let nested = descendants(outer)
            .into_iter()
            .filter(|node| is_function_declaration(*node))
            .filter_map(|node| {
                let name = node.child_by_field_name("name")?;
                (enclosing_function(node).is_some_and(|owner| owner.id() == outer.id()))
                    .then(|| node_text(source, name).to_owned())
            })
            .collect::<Vec<_>>();
        if nested.is_empty() {
            continue;
        }
        for default in descendants(parameters).into_iter().filter_map(|node| {
            match node.kind() {
                "assignment_pattern" => node.child_by_field_name("right"),
                // TypeScript wraps a typed default in optional_parameter and
                // stores its initializer in `value` instead of using the
                // JavaScript assignment_pattern node.
                "optional_parameter" | "required_parameter" => {
                    node.child_by_field_name("value")
                }
                _ => None,
            }
        })
        {
            for call in descendants(default)
                .into_iter()
                .filter(|node| node.kind() == "call_expression")
            {
                let Some(callee) = call.child_by_field_name("function") else {
                    continue;
                };
                if callee.kind() == "identifier"
                    && nested.iter().any(|name| name == node_text(source, callee))
                {
                    ranges.push(node_range(call));
                }
            }
        }
    }
    ranges
}

fn var_declarations<'tree>(root: Node<'tree>) -> Vec<Node<'tree>> {
    let mut declarations = Vec::new();
    for node in descendants(root) {
        if node.kind() != "variable_declaration" {
            continue;
        }
        for declarator in named_children(node)
            .into_iter()
            .filter(|child| child.kind() == "variable_declarator")
        {
            declarations.extend(binding_identifiers(declarator.child_by_field_name("name")));
        }
    }
    declarations
}

fn binding_identifiers(root: Option<Node<'_>>) -> Vec<Node<'_>> {
    let Some(root) = root else {
        return Vec::new();
    };
    let mut pending = vec![root];
    let mut names = Vec::new();
    while let Some(node) = pending.pop() {
        if is_binding_identifier(node) {
            names.push(node);
            continue;
        }
        pending.extend(named_children(node));
    }
    names
}

fn is_binding_identifier(node: Node<'_>) -> bool {
    if !matches!(node.kind(), "identifier" | "type_identifier" | "shorthand_property_identifier_pattern")
    {
        return false;
    }
    let Some(parent) = node.parent() else {
        return true;
    };
    parent.kind() != "pair_pattern"
        || parent
            .child_by_field_name("key")
            .is_none_or(|key| key.id() != node.id())
}

fn initializer_references_name(initializer: Node<'_>, source: &str, name: &str) -> bool {
    descendants(initializer).into_iter().any(|node| {
        is_identifier_reference(node) && node_text(source, node) == name
    })
}

fn is_identifier_reference(node: Node<'_>) -> bool {
    if !matches!(node.kind(), "identifier" | "shorthand_property_identifier") {
        return false;
    }
    let Some(parent) = node.parent() else {
        return true;
    };
    if matches!(parent.kind(), "property_identifier" | "private_property_identifier") {
        return false;
    }
    if parent.kind() == "member_expression"
        && parent
            .child_by_field_name("property")
            .is_some_and(|property| property.id() == node.id())
    {
        return false;
    }
    if parent.kind() == "pair"
        && parent
            .child_by_field_name("key")
            .is_some_and(|key| key.id() == node.id())
    {
        return false;
    }
    if parent.kind() == "pair_pattern"
        && parent
            .child_by_field_name("key")
            .is_some_and(|key| key.id() == node.id())
    {
        return false;
    }
    if is_declaration_name(node) || is_import_name(node) {
        return false;
    }
    true
}

fn is_simple_assignment_target(node: Node<'_>) -> bool {
    node.parent().is_some_and(|parent| {
        parent.kind() == "assignment_expression"
            && parent
                .child_by_field_name("left")
                .is_some_and(|left| left.id() == node.id())
    })
}

fn is_declaration_name(node: Node<'_>) -> bool {
    let Some(parent) = node.parent() else {
        return false;
    };
    (parent.child_by_field_name("name").is_some_and(|name| name.id() == node.id()))
        && matches!(
            parent.kind(),
            "function_declaration"
                | "generator_function_declaration"
                | "function_expression"
                | "generator_function"
                | "class_declaration"
                | "abstract_class_declaration"
                | "class"
                | "variable_declarator"
        )
}

fn is_import_name(node: Node<'_>) -> bool {
    let Some(parent) = node.parent() else {
        return false;
    };
    matches!(
        parent.kind(),
        "import_specifier" | "namespace_import" | "import_clause"
    )
}

fn function_declaration_scope(node: Node<'_>, root: Node<'_>, source: &str) -> ScopeId {
    if strict_context(node, root, source) {
        scope_for_reference(node.parent().unwrap_or(node), root, source)
    } else {
        function_scope_for(node, root)
    }
}

fn scope_for_reference(node: Node<'_>, root: Node<'_>, source: &str) -> ScopeId {
    let mut current = Some(node);
    while let Some(candidate) = current {
        match candidate.kind() {
            "program" => return file_scope(root),
            kind if is_function_node(kind) => return scope_id(candidate, ScopeKind::Function),
            "statement_block" => {
                if candidate
                    .parent()
                    .is_some_and(|parent| is_function_node(parent.kind()))
                {
                    return candidate
                        .parent()
                        .map_or_else(|| scope_id(candidate, ScopeKind::Block), |parent| {
                            scope_id(parent, ScopeKind::Function)
                        });
                }
                return scope_id(candidate, ScopeKind::Block);
            }
            "switch_body" => return scope_id(candidate, ScopeKind::Block),
            "catch_clause" => return scope_id(candidate, ScopeKind::Catch),
            "for_in_statement" | "for_statement" | "for_of_statement" => {
                return scope_id(candidate, ScopeKind::Loop)
            }
            _ => current = candidate.parent(),
        }
    }
    let _ = source;
    file_scope(root)
}

fn function_scope_for(node: Node<'_>, root: Node<'_>) -> ScopeId {
    let mut current = node.parent();
    while let Some(candidate) = current {
        if is_function_node(candidate.kind()) {
            return scope_id(candidate, ScopeKind::Function);
        }
        current = candidate.parent();
    }
    file_scope(root)
}

fn strict_context(node: Node<'_>, root: Node<'_>, source: &str) -> bool {
    let mut current = Some(node);
    while let Some(candidate) = current {
        if is_function_node(candidate.kind())
            && candidate
                .child_by_field_name("body")
                .is_some_and(|body| has_use_strict(body, source))
        {
            return true;
        }
        current = candidate.parent();
    }
    is_module(root) || has_use_strict(root, source)
}

fn has_use_strict(container: Node<'_>, source: &str) -> bool {
    let Some(first) = named_children(container).into_iter().next() else {
        return false;
    };
    if first.kind() != "expression_statement" {
        return false;
    }
    let Some(expression) = first.named_child(0) else {
        return false;
    };
    matches!(expression.kind(), "string" | "string_fragment")
        && node_text(source, expression).trim_matches(['"', '\'']) == "use strict"
}

fn is_module(root: Node<'_>) -> bool {
    named_children(root).into_iter().any(|node| {
        matches!(
            node.kind(),
            "import_statement" | "export_statement" | "export_default_declaration"
        )
    })
}

fn has_dynamic_scope(root: Node<'_>, source: &str) -> bool {
    !dynamic_scope_ranges(root, source).is_empty()
}

#[derive(Debug)]
struct DynamicScope {
    kind: &'static str,
    range: Range,
}

fn dynamic_scope_ranges(root: Node<'_>, source: &str) -> Vec<DynamicScope> {
    let mut scopes = descendants(root)
        .into_iter()
        .filter_map(|node| {
            if matches!(node.kind(), "with_statement" | "with_clause") {
                return Some(DynamicScope {
                    kind: "with",
                    range: node_range(node),
                });
            }
            (node.kind() == "call_expression")
                .then(|| node.child_by_field_name("function"))
                .flatten()
                .filter(|callee| {
                    callee.kind() == "identifier" && node_text(source, *callee) == "eval"
                })
                .map(|_| DynamicScope {
                    kind: "direct_eval",
                    range: node_range(node),
                })
        })
        .collect::<Vec<_>>();
    scopes.sort_by_key(|scope| scope.range.start_byte);
    scopes
}

fn file_scope(root: Node<'_>) -> ScopeId {
    scope_id(root, ScopeKind::File)
}

fn scope_id(node: Node<'_>, kind: ScopeKind) -> ScopeId {
    ScopeId {
        start_byte: node.start_byte(),
        end_byte: node.end_byte(),
        kind,
    }
}

fn is_variable_declaration(node: Node<'_>) -> bool {
    matches!(node.kind(), "variable_declaration" | "lexical_declaration")
}

fn is_function_declaration(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "function_declaration" | "generator_function_declaration"
    )
}

fn is_function_node(kind: &str) -> bool {
    matches!(
        kind,
        "function_declaration"
            | "generator_function_declaration"
            | "function_expression"
            | "generator_function"
            | "arrow_function"
            | "method_definition"
    )
}

fn has_function_body(function: Node<'_>) -> bool {
    function
        .child_by_field_name("body")
        .is_some_and(|body| !body.is_missing() && !body.is_error())
}

fn enclosing_function(node: Node<'_>) -> Option<Node<'_>> {
    let mut current = node.parent();
    while let Some(candidate) = current {
        if is_function_node(candidate.kind()) {
            return Some(candidate);
        }
        current = candidate.parent();
    }
    None
}

fn node_text<'a>(source: &'a str, node: Node<'_>) -> &'a str {
    source
        .get(node.start_byte()..node.end_byte())
        .expect("tree-sitter node range is within its source")
}

fn descendants(root: Node<'_>) -> Vec<Node<'_>> {
    let mut pending = vec![root];
    let mut nodes = Vec::new();
    while let Some(node) = pending.pop() {
        nodes.push(node);
        pending.extend(named_children(node));
    }
    nodes
}

fn named_children(node: Node<'_>) -> Vec<Node<'_>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor).collect()
}

fn node_range(node: Node<'_>) -> Range {
    Range {
        start_byte: node.start_byte(),
        end_byte: node.end_byte(),
        start_line: node.start_position().row.saturating_add(1),
        end_line: node.end_position().row.saturating_add(1),
    }
}

fn missing_this_qualifiers(tree: &Tree, source: &str) -> Vec<Range> {
    let root = tree.root_node();
    descendants(root)
        .into_iter()
        .filter(|node| node.kind() == "call_expression")
        .filter_map(|call| {
            let callee = call.child_by_field_name("function")?;
            if callee.kind() != "identifier" {
                return None;
            }
            let name = class_node_text(callee, source)?;
            let method = direct_enclosing_method(call)?;
            let class = enclosing_class(method)?;
            if !class_methods(class)
                .iter()
                .any(|member| method_name(*member, source).as_deref() == Some(name))
            {
                return None;
            }
            if has_with_ancestor(call)
                || method_has_binding(method, name, source)
                || file_has_binding(root, name, source)
            {
                return None;
            }
            Some(node_range(call))
        })
        .collect()
}

fn mixed_static_instance_this_accesses(tree: &Tree, source: &str) -> Vec<Range> {
    descendants(tree.root_node())
        .into_iter()
        .filter_map(|access| {
            let object = access.child_by_field_name("object")?;
            if object.kind() != "this" {
                return None;
            }
            let (_, property_name) = static_member_property(access, source)?;
            let from_method = direct_enclosing_method(access)?;
            let class = enclosing_class(from_method)?;
            let from_static = is_static_member(from_method);
            let target_members = class_members_named(class, source, &property_name);
            if target_members.is_empty()
                || target_members
                    .iter()
                    .any(|member| is_static_member(*member) == from_static)
                || is_lvalue(access)
            {
                return None;
            }
            Some(node_range(access))
        })
        .collect()
}

struct ObjectProperty<'tree> {
    node: Node<'tree>,
    name: String,
    kind: u8,
    initializer: Option<Node<'tree>>,
    order: usize,
}

fn overwritten_properties(tree: &Tree, source: &str) -> Vec<Range> {
    let mut ranges = Vec::new();
    for object in descendants(tree.root_node()) {
        if object.kind() != "object" {
            continue;
        }
        let properties = named_children(object)
            .into_iter()
            .enumerate()
            .filter_map(|(order, node)| object_property(node, source, order))
            .collect::<Vec<_>>();
        for property in &properties {
            let Some(last) = properties.iter().rev().find(|candidate| {
                candidate.name == property.name && candidate.kind == property.kind
            }) else {
                continue;
            };
            if last.order == property.order {
                continue;
            }
            if property.initializer.zip(last.initializer).is_some_and(
                |(left, right)| structurally_same(left, right, source),
            ) {
                continue;
            }
            ranges.push(node_range(property.node));
        }
    }
    ranges
}

fn object_property<'tree>(
    node: Node<'tree>,
    source: &str,
    order: usize,
) -> Option<ObjectProperty<'tree>> {
    // Literal, shorthand, and method keys have stable identity. Computed
    // keys stay incomplete when the shared helper cannot decode them.
    if !matches!(
        node.kind(),
        "pair" | "method_definition" | "shorthand_property_identifier"
    ) {
        return None;
    }
    let name = ts_object_literal_property_name(node, source)?;
    let kind = object_property_kind(node);
    Some(ObjectProperty {
        node,
        name,
        kind,
        initializer: node
            .child_by_field_name("value")
            .or_else(|| (node.kind() == "method_definition").then_some(node)),
        order,
    })
}

fn object_property_kind(node: Node<'_>) -> u8 {
    if node.kind() != "method_definition" {
        return 0;
    }
    children(node)
        .into_iter()
        .find_map(|child| match child.kind() {
            "get" => Some(1),
            "set" => Some(2),
            _ => None,
        })
        .unwrap_or(0)
}

fn structurally_same(left: Node<'_>, right: Node<'_>, source: &str) -> bool {
    let mut pending = vec![(left, right)];
    while let Some((left, right)) = pending.pop() {
        if left.kind() != right.kind() || left.child_count() != right.child_count() {
            return false;
        }
        if left.child_count() == 0 && class_node_text(left, source) != class_node_text(right, source) {
            return false;
        }
        for index in 0..left.child_count() {
            let Some(left_child) = left.child(index) else {
                return false;
            };
            let Some(right_child) = right.child(index) else {
                return false;
            };
            pending.push((left_child, right_child));
        }
    }
    true
}

fn misspelled_identifiers(tree: &Tree, source: &str) -> Vec<Range> {
    // The generated CodeQL typo database is not an engine asset. This closed
    // relation keeps the same normalized-part/co-occurrence shape with a
    // bounded one-edit Damerau candidate relation.
    let identifiers = descendants(tree.root_node())
        .into_iter()
        .filter(|node| is_identifier_node(*node))
        .flat_map(|node| {
            identifier_parts(node, source)
                .into_iter()
                .map(move |part| (node, part))
        })
        .collect::<Vec<_>>();
    let mut counts = Vec::<(String, usize)>::new();
    for (_, part) in &identifiers {
        increment_count(&mut counts, &part.normalized);
    }

    let mut ranges = Vec::new();
    for (_, wrong) in &identifiers {
        if wrong.normalized.chars().count() <= 3 {
            continue;
        }
        let wrong_count = count_for(&counts, &wrong.normalized);
        let has_correction = identifiers.iter().any(|(_, right)| {
            right.normalized != wrong.normalized
                && count_for(&counts, &right.normalized) > wrong_count
                && likely_typo(&wrong.normalized, &right.normalized)
        });
        if !has_correction {
            continue;
        }
        ranges.push(part_range(
            wrong.node,
            wrong.start_offset,
            wrong.end_offset,
        ));
    }
    ranges
}

fn likely_typo(wrong: &str, right: &str) -> bool {
    let wrong_first = wrong.chars().next();
    let right_first = right.chars().next();
    let wrong_last = wrong.chars().last();
    let right_last = right.chars().last();
    damerau_levenshtein(wrong, right) == 1
        && (wrong_first == right_first || wrong_last == right_last)
}

fn identifier_parts<'tree>(node: Node<'tree>, source: &str) -> Vec<IdentifierPartRef<'tree>> {
    let Some(name) = class_node_text(node, source) else {
        return Vec::new();
    };
    let characters = name.char_indices().collect::<Vec<_>>();
    let mut parts = Vec::new();
    let mut index = 0;
    while index < characters.len() {
        let character = characters[index].1;
        if !character.is_ascii_alphabetic() {
            index += 1;
            continue;
        }

        let mut start = index;
        if character.is_ascii_uppercase() {
            let uppercase_start = index;
            while index < characters.len() && characters[index].1.is_ascii_uppercase() {
                index += 1;
            }
            let uppercase_end = index;
            if index < characters.len() && characters[index].1.is_ascii_lowercase() {
                // Keep the final capital with the following lower-case word:
                // `countItems` is `count` + `Items`, and `HTTPServer` is
                // `HTTP` + `Server`.
                if uppercase_end - uppercase_start > 1 {
                    index = uppercase_end - 1;
                    let end = characters[index].0;
                    push_identifier_part(&mut parts, node, source, characters[start].0, end);
                    start = index;
                }
                while index < characters.len() && characters[index].1.is_ascii_lowercase() {
                    index += 1;
                }
            }
        } else {
            while index < characters.len() && characters[index].1.is_ascii_lowercase() {
                index += 1;
            }
        }

        let end = if index < characters.len() {
            characters[index].0
        } else {
            name.len()
        };
        push_identifier_part(&mut parts, node, source, characters[start].0, end);
    }
    parts
}

struct IdentifierPartRef<'tree> {
    node: Node<'tree>,
    normalized: String,
    start_offset: usize,
    end_offset: usize,
}

fn push_identifier_part<'tree>(
    parts: &mut Vec<IdentifierPartRef<'tree>>,
    node: Node<'tree>,
    source: &str,
    start_offset: usize,
    end_offset: usize,
) {
    let Some(value) = source
        .get(node.start_byte() + start_offset..node.start_byte() + end_offset)
    else {
        return;
    };
    if value.is_empty() {
        return;
    }
    parts.push(IdentifierPartRef {
        node,
        normalized: value.to_lowercase(),
        start_offset,
        end_offset,
    });
}

fn is_identifier_node(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "identifier"
            | "property_identifier"
            | "private_property_identifier"
            | "shorthand_property_identifier"
            | "type_identifier"
            | "nested_identifier"
    )
}

fn increment_count(counts: &mut Vec<(String, usize)>, name: &str) {
    if let Some((_, count)) = counts.iter_mut().find(|(candidate, _)| candidate == name) {
        *count = count.saturating_add(1);
    } else {
        counts.push((name.to_string(), 1));
    }
}

fn count_for(counts: &[(String, usize)], name: &str) -> usize {
    counts
        .iter()
        .find(|(candidate, _)| candidate == name)
        .map_or(0, |(_, count)| *count)
}

fn method_has_binding(method: Node<'_>, name: &str, source: &str) -> bool {
    method
        .child_by_field_name("parameters")
        .is_some_and(|parameters| binding_pattern_contains(parameters, name, source))
        || method
            .child_by_field_name("body")
            .is_some_and(|body| body_has_binding(body, name, source))
}

fn body_has_binding(body: Node<'_>, name: &str, source: &str) -> bool {
    let mut pending = vec![body];
    while let Some(node) = pending.pop() {
        if node.id() != body.id() && is_nested_function_or_class(node) {
            continue;
        }
        if declaration_binds_name(node, name, source) {
            return true;
        }
        pending.extend(named_children(node));
    }
    false
}

fn file_has_binding(root: Node<'_>, name: &str, source: &str) -> bool {
    let mut pending = vec![root];
    while let Some(node) = pending.pop() {
        if node.id() != root.id() && is_nested_function_or_class(node) {
            continue;
        }
        if declaration_binds_name(node, name, source) {
            return true;
        }
        pending.extend(named_children(node));
    }
    false
}

fn declaration_binds_name(node: Node<'_>, name: &str, source: &str) -> bool {
    let binding = match node.kind() {
        "variable_declarator" | "function_declaration" | "class_declaration"
        | "abstract_class_declaration" => node
            .child_by_field_name("name")
            .or_else(|| node.child_by_field_name("pattern")),
        "import_specifier" | "namespace_import" | "import_clause" => {
            node.child_by_field_name("alias")
                .or_else(|| node.child_by_field_name("name"))
        }
        _ => None,
    };
    binding.is_some_and(|binding| binding_pattern_contains(binding, name, source))
}

fn binding_pattern_contains(node: Node<'_>, name: &str, source: &str) -> bool {
    let mut pending = vec![node];
    while let Some(node) = pending.pop() {
        if is_identifier_node(node) && class_node_text(node, source) == Some(name) {
            return true;
        }
        pending.extend(named_children(node));
    }
    false
}

fn direct_enclosing_method(node: Node<'_>) -> Option<Node<'_>> {
    let mut current = node.parent();
    while let Some(parent) = current {
        if is_method(parent) {
            return Some(parent);
        }
        if is_nested_function_or_class(parent) {
            return None;
        }
        current = parent.parent();
    }
    None
}

fn enclosing_class(node: Node<'_>) -> Option<Node<'_>> {
    let mut current = node.parent();
    while let Some(parent) = current {
        if is_class(parent) {
            return Some(parent);
        }
        if is_nested_function_or_class(parent) && !is_method(parent) {
            return None;
        }
        current = parent.parent();
    }
    None
}

fn class_methods(class: Node<'_>) -> Vec<Node<'_>> {
    class
        .child_by_field_name("body")
        .map(named_children)
        .unwrap_or_default()
        .into_iter()
        .filter(|node| is_method(*node))
        .collect()
}

fn class_members_named<'tree>(
    class: Node<'tree>,
    source: &str,
    name: &str,
) -> Vec<Node<'tree>> {
    class
        .child_by_field_name("body")
        .map(named_children)
        .unwrap_or_default()
        .into_iter()
        .filter(|node| is_method(*node) || is_field(*node))
        .filter(|member| member_name(*member, source).as_deref() == Some(name))
        .collect()
}

fn method_name(node: Node<'_>, source: &str) -> Option<String> {
    let name = node.child_by_field_name("name")?;
    static_property_name(name, source).map(|(_, value)| value)
}

fn member_name(node: Node<'_>, source: &str) -> Option<String> {
    let name = node
        .child_by_field_name("name")
        .or_else(|| node.child_by_field_name("property"))?;
    static_property_name(name, source).map(|(_, value)| value)
}

fn is_static_member(node: Node<'_>) -> bool {
    children(node)
        .into_iter()
        .any(|child| matches!(child.kind(), "static" | "static get"))
}

fn is_lvalue(node: Node<'_>) -> bool {
    let Some(parent) = node.parent() else {
        return false;
    };
    (parent.kind() == "assignment_expression"
        && parent.child_by_field_name("left").is_some_and(|left| left.id() == node.id()))
        || parent.kind() == "update_expression"
        || parent.kind() == "augmented_assignment_expression"
}

fn has_with_ancestor(node: Node<'_>) -> bool {
    let mut current = node.parent();
    while let Some(parent) = current {
        if parent.kind() == "with_statement" {
            return true;
        }
        current = parent.parent();
    }
    false
}

fn is_method(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "method_definition" | "method_signature" | "abstract_method_signature"
    )
}

fn is_field(node: Node<'_>) -> bool {
    matches!(node.kind(), "field_definition" | "public_field_definition")
}

fn is_class(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "class" | "class_declaration" | "abstract_class_declaration"
    )
}

fn is_nested_function_or_class(node: Node<'_>) -> bool {
    is_class(node)
        || matches!(
            node.kind(),
            "function_declaration"
                | "function_expression"
                | "generator_function_declaration"
                | "generator_function"
                | "arrow_function"
        )
}

fn class_node_text<'a>(node: Node<'_>, source: &'a str) -> Option<&'a str> {
    source.get(node.byte_range())
}

fn part_range(node: Node<'_>, start_offset: usize, end_offset: usize) -> Range {
    let start_byte = node.start_byte().saturating_add(start_offset);
    let end_byte = node.start_byte().saturating_add(end_offset);
    Range {
        start_byte,
        end_byte,
        start_line: node.start_position().row.saturating_add(1),
        end_line: node.end_position().row.saturating_add(1),
    }
}

fn children(node: Node<'_>) -> Vec<Node<'_>> {
    let mut cursor = node.walk();
    node.children(&mut cursor).collect()
}
