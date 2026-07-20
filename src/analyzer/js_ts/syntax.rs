use crate::analyzer::Range;
use crate::analyzer::js_ts::imports::{
    CommonJsRequireBindingKind, commonjs_require_module_specifier_from_declarator,
    parse_commonjs_require_bindings_from_node,
};
use crate::analyzer::usages::{ImportBinder, ImportBinding, ImportKind};
use crate::hash::HashMap;
use tree_sitter::{Node, Tree};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct JsTsLexicalBindingScope {
    start_byte: usize,
    end_byte: usize,
}

/// Tree-sitter-derived lexical bindings, indexed by the source range in which
/// each name shadows an outer/global binding. Declaration order is deliberately
/// irrelevant: `var` is hoisted and lexical declarations are in the TDZ for
/// their entire scope.
pub(crate) struct JsTsLexicalBindingIndex {
    scopes_by_name: HashMap<String, Vec<JsTsLexicalBindingScope>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct JsTsDirectPropertyDefinition<'tree> {
    pub(crate) receiver: JsTsStaticMemberReceiver<'tree>,
    pub(crate) property_range: Range,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct JsTsStaticMemberReceiver<'tree> {
    pub(crate) root: Node<'tree>,
    pub(crate) members: Vec<Node<'tree>>,
}

impl JsTsLexicalBindingIndex {
    pub(crate) fn build(root: Node<'_>, source: &str) -> Self {
        let mut index = Self {
            scopes_by_name: HashMap::default(),
        };
        let mut stack = vec![root];
        while let Some(node) = stack.pop() {
            match node.kind() {
                "import_statement" => {
                    let mut binder = ImportBinder::empty();
                    visit_import_statement(node, source, &mut binder);
                    let scope = node_scope(root);
                    for name in binder.bindings.keys() {
                        index.insert(name, scope);
                    }
                }
                "variable_declarator" => {
                    if let Some(pattern) = node.child_by_field_name("name")
                        && let Some(scope) = variable_binding_scope(node)
                    {
                        index.insert_pattern(pattern, source, scope);
                    }
                }
                "function_declaration" | "generator_function_declaration" | "class_declaration" => {
                    if let Some(name) = node.child_by_field_name("name")
                        && let Some(scope) = enclosing_lexical_scope(node)
                    {
                        index.insert_pattern(name, source, scope);
                    }
                    index.insert_parameters(node, source);
                }
                "function_expression"
                | "generator_function"
                | "arrow_function"
                | "method_definition" => {
                    if matches!(node.kind(), "function_expression" | "generator_function")
                        && let Some(name) = node.child_by_field_name("name")
                    {
                        index.insert_pattern(name, source, node_scope(node));
                    }
                    index.insert_parameters(node, source);
                }
                "class" => {
                    if let Some(name) = node.child_by_field_name("name") {
                        index.insert_pattern(name, source, node_scope(node));
                    }
                }
                "catch_clause" => {
                    if let Some(parameter) = node.child_by_field_name("parameter") {
                        index.insert_pattern(parameter, source, node_scope(node));
                    }
                }
                _ => {}
            }

            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                stack.push(child);
            }
        }
        index
    }

    pub(crate) fn is_bound_at(&self, name: &str, byte: usize) -> bool {
        self.binding_scope_at(name, byte).is_some()
    }

    pub(crate) fn binding_scope_at(
        &self,
        name: &str,
        byte: usize,
    ) -> Option<JsTsLexicalBindingScope> {
        self.scopes_by_name
            .get(name)?
            .iter()
            .copied()
            .filter(|scope| scope.start_byte <= byte && byte < scope.end_byte)
            .min_by_key(|scope| scope.end_byte - scope.start_byte)
    }

    fn insert_parameters(&mut self, function: Node<'_>, source: &str) {
        let Some(parameters) = function.child_by_field_name("parameters") else {
            return;
        };
        self.insert_pattern(parameters, source, node_scope(function));
    }

    fn insert_pattern(&mut self, pattern: Node<'_>, source: &str, scope: JsTsLexicalBindingScope) {
        let mut stack = vec![pattern];
        while let Some(node) = stack.pop() {
            match node.kind() {
                "identifier" | "shorthand_property_identifier_pattern" => {
                    let name = slice(node, source);
                    if !name.is_empty() {
                        self.insert(name, scope);
                    }
                }
                "required_parameter" | "optional_parameter" => {
                    if let Some(pattern) = node
                        .child_by_field_name("pattern")
                        .or_else(|| node.child_by_field_name("name"))
                    {
                        stack.push(pattern);
                    }
                }
                "assignment_pattern" | "object_assignment_pattern" => {
                    if let Some(left) = node.child_by_field_name("left") {
                        stack.push(left);
                    }
                }
                "pair_pattern" => {
                    if let Some(value) = node.child_by_field_name("value") {
                        stack.push(value);
                    }
                }
                "formal_parameters" | "object_pattern" | "array_pattern" | "rest_pattern" => {
                    let mut cursor = node.walk();
                    for child in node.named_children(&mut cursor) {
                        stack.push(child);
                    }
                }
                _ => {}
            }
        }
    }

    fn insert(&mut self, name: &str, scope: JsTsLexicalBindingScope) {
        let scopes = self.scopes_by_name.entry(name.to_string()).or_default();
        if !scopes.contains(&scope) {
            scopes.push(scope);
        }
    }
}

pub(crate) fn direct_property_definitions<'tree>(
    root: Node<'tree>,
    source: &str,
    target_ranges: &[Range],
    target_member: &str,
) -> Vec<JsTsDirectPropertyDefinition<'tree>> {
    let mut definitions = Vec::new();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        let receiver = match node.kind() {
            "assignment_expression" | "augmented_assignment_expression" => node
                .child_by_field_name("left")
                .and_then(|left| direct_assignment_receiver(left, source, target_member)),
            "pair" => direct_object_pair_receiver(node, source, target_member),
            _ => None,
        };
        if let Some((receiver, property)) = receiver
            && target_ranges
                .iter()
                .any(|range| range_contains_node(range, property))
        {
            let definition = JsTsDirectPropertyDefinition {
                receiver,
                property_range: Range {
                    start_byte: property.start_byte(),
                    end_byte: property.end_byte(),
                    start_line: property.start_position().row,
                    end_line: property.end_position().row,
                },
            };
            definitions.push(definition);
        }

        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            stack.push(child);
        }
    }
    definitions
}

fn direct_assignment_receiver<'tree>(
    left: Node<'tree>,
    source: &str,
    target_member: &str,
) -> Option<(JsTsStaticMemberReceiver<'tree>, Node<'tree>)> {
    if left.kind() != "member_expression" {
        return None;
    }
    let receiver = left.child_by_field_name("object")?;
    let property = left.child_by_field_name("property")?;
    if slice(property, source) != target_member {
        return None;
    }
    static_member_receiver(receiver, source).map(|receiver| (receiver, property))
}

fn direct_object_pair_receiver<'tree>(
    pair: Node<'tree>,
    source: &str,
    target_member: &str,
) -> Option<(JsTsStaticMemberReceiver<'tree>, Node<'tree>)> {
    let property = pair.child_by_field_name("key")?;
    if slice(property, source) != target_member {
        return None;
    }
    let object = pair.parent().filter(|parent| parent.kind() == "object")?;
    let declarator = object
        .parent()
        .filter(|parent| parent.kind() == "variable_declarator")?;
    if declarator
        .child_by_field_name("value")
        .is_none_or(|value| value.id() != object.id())
    {
        return None;
    }
    let receiver = declarator.child_by_field_name("name")?;
    let receiver = static_member_receiver(receiver, source)?;
    receiver.members.is_empty().then_some((receiver, property))
}

pub(crate) fn static_member_receiver<'tree>(
    node: Node<'tree>,
    source: &str,
) -> Option<JsTsStaticMemberReceiver<'tree>> {
    let mut current = node;
    let mut members = Vec::new();
    while current.kind() == "member_expression" {
        let property = current.child_by_field_name("property")?;
        if property.kind() != "property_identifier" || slice(property, source).is_empty() {
            return None;
        }
        members.push(property);
        current = current.child_by_field_name("object")?;
    }
    if current.kind() != "identifier" || slice(current, source).is_empty() {
        return None;
    }
    members.reverse();
    Some(JsTsStaticMemberReceiver {
        root: current,
        members,
    })
}

fn range_contains_node(range: &Range, node: Node<'_>) -> bool {
    range.start_byte <= node.start_byte() && node.end_byte() <= range.end_byte
}

fn node_scope(node: Node<'_>) -> JsTsLexicalBindingScope {
    JsTsLexicalBindingScope {
        start_byte: node.start_byte(),
        end_byte: node.end_byte(),
    }
}

fn variable_binding_scope(node: Node<'_>) -> Option<JsTsLexicalBindingScope> {
    let is_var = node
        .parent()
        .is_some_and(|parent| parent.kind() == "variable_declaration");
    let mut current = node.parent();
    while let Some(parent) = current {
        let is_scope = if is_var {
            matches!(
                parent.kind(),
                "program"
                    | "function_declaration"
                    | "generator_function_declaration"
                    | "function_expression"
                    | "generator_function"
                    | "arrow_function"
                    | "method_definition"
            )
        } else {
            matches!(
                parent.kind(),
                "program"
                    | "statement_block"
                    | "for_statement"
                    | "for_in_statement"
                    | "switch_body"
                    | "catch_clause"
            )
        };
        if is_scope {
            return Some(node_scope(parent));
        }
        current = parent.parent();
    }
    None
}

fn enclosing_lexical_scope(node: Node<'_>) -> Option<JsTsLexicalBindingScope> {
    let mut current = node.parent();
    while let Some(parent) = current {
        if matches!(parent.kind(), "program" | "statement_block") {
            return Some(node_scope(parent));
        }
        current = parent.parent();
    }
    None
}

pub(crate) fn slice<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    source.get(node.start_byte()..node.end_byte()).unwrap_or("")
}

pub(crate) fn nested_type_identifier_parts(node: Node<'_>) -> Option<(Node<'_>, Node<'_>)> {
    (node.kind() == "nested_type_identifier").then_some(())?;
    Some((
        node.child_by_field_name("module")?,
        node.child_by_field_name("name")?,
    ))
}

pub(crate) fn is_lexically_nested_type_declaration(node: Node<'_>) -> bool {
    if !matches!(
        node.kind(),
        "class_declaration"
            | "abstract_class_declaration"
            | "interface_declaration"
            | "enum_declaration"
            | "type_alias_declaration"
            | "internal_module"
    ) {
        return false;
    }
    let mut current = node.parent();
    while let Some(parent) = current {
        if matches!(
            parent.kind(),
            "statement_block"
                | "function_declaration"
                | "function_expression"
                | "generator_function"
                | "arrow_function"
                | "method_definition"
        ) {
            return true;
        }
        if parent.kind() == "program" {
            return false;
        }
        current = parent.parent();
    }
    false
}

pub(crate) fn is_declaration_identifier(node: Node<'_>) -> bool {
    let Some(parent) = node.parent() else {
        return false;
    };
    let parent_kind = parent.kind();
    if matches!(
        parent_kind,
        "variable_declarator"
            | "function_declaration"
            | "class_declaration"
            | "interface_declaration"
            | "enum_declaration"
            | "type_alias_declaration"
            | "method_definition"
            | "method_signature"
            | "abstract_method_signature"
            | "public_field_definition"
            | "property_signature"
            | "field_definition"
            | "import_specifier"
            | "namespace_import"
            | "import_clause"
            | "labeled_statement"
            | "function_signature"
    ) {
        if let Some(name_node) = parent
            .child_by_field_name("name")
            .or_else(|| parent.child_by_field_name("property"))
            && name_node.id() == node.id()
        {
            return true;
        }
        if matches!(
            parent_kind,
            "import_specifier" | "namespace_import" | "import_clause"
        ) {
            return true;
        }
    }
    if matches!(
        parent_kind,
        "formal_parameters"
            | "required_parameter"
            | "optional_parameter"
            | "rest_pattern"
            | "object_pattern"
            | "array_pattern"
            | "pair_pattern"
            | "shorthand_property_identifier_pattern"
    ) {
        return true;
    }
    if parent_kind == "assignment_pattern"
        && let Some(pattern) = parent.named_child(0)
    {
        return pattern.start_byte() <= node.start_byte() && node.end_byte() <= pattern.end_byte();
    }
    false
}

pub(crate) fn is_explicit_object_literal_key(node: Node<'_>) -> bool {
    let Some(parent) = node.parent() else {
        return false;
    };
    parent.kind() == "pair"
        && parent
            .child_by_field_name("key")
            .is_some_and(|key| key.id() == node.id())
}

pub(crate) fn is_property_key_in_member(node: Node<'_>) -> bool {
    let Some(parent) = node.parent() else {
        return false;
    };
    if parent.kind() != "member_expression" {
        return false;
    }
    parent
        .child_by_field_name("property")
        .map(|property| property.id() == node.id())
        .unwrap_or(false)
}

pub(crate) fn is_object_in_member_expression(node: Node<'_>) -> bool {
    let Some(parent) = node.parent() else {
        return false;
    };
    if parent.kind() != "member_expression" {
        return false;
    }
    parent
        .child_by_field_name("object")
        .map(|object| object.id() == node.id())
        .unwrap_or(false)
}

pub(crate) fn compute_import_binder(source: &str, tree: &Tree) -> ImportBinder {
    let mut binder = ImportBinder::empty();
    let root = tree.root_node();

    for index_id in 0..root.named_child_count() {
        let Some(child) = root.named_child(index_id) else {
            continue;
        };
        if child.kind() == "import_statement" {
            visit_import_statement(child, source, &mut binder);
        } else if matches!(child.kind(), "lexical_declaration" | "variable_declaration") {
            visit_commonjs_require_statement(child, source, &mut binder);
        }
    }
    binder
}

fn visit_commonjs_require_statement(node: Node<'_>, source: &str, binder: &mut ImportBinder) {
    for binding in parse_commonjs_require_bindings_from_node(node, source) {
        let (kind, imported_name) = match binding.kind {
            CommonJsRequireBindingKind::ModuleObject => (ImportKind::CommonJsRequire, None),
            CommonJsRequireBindingKind::Named => (ImportKind::Named, Some(binding.imported_name)),
        };
        binder.bindings.insert(
            binding.local_name,
            ImportBinding {
                module_specifier: binding.module_specifier,
                kind,
                imported_name,
            },
        );
    }
}

pub(crate) fn is_commonjs_require_declarator(node: Node<'_>, source: &str) -> bool {
    node.kind() == "variable_declarator"
        && commonjs_require_module_specifier_from_declarator(node, source).is_some()
}

fn visit_import_statement(node: Node<'_>, source: &str, binder: &mut ImportBinder) {
    let Some(source_node) = node.child_by_field_name("source") else {
        return;
    };
    let module_specifier = unquote(slice(source_node, source));
    if module_specifier.is_empty() {
        return;
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.kind() != "import_clause" {
            continue;
        }
        let mut clause_cursor = child.walk();
        for clause_child in child.named_children(&mut clause_cursor) {
            match clause_child.kind() {
                "identifier" => {
                    let local = slice(clause_child, source).to_string();
                    if !local.is_empty() {
                        binder.bindings.insert(
                            local,
                            ImportBinding {
                                module_specifier: module_specifier.clone(),
                                kind: ImportKind::Default,
                                imported_name: None,
                            },
                        );
                    }
                }
                "namespace_import" => {
                    let mut ns_cursor = clause_child.walk();
                    let identifier = clause_child
                        .named_children(&mut ns_cursor)
                        .find(|node| node.kind() == "identifier")
                        .map(|node| slice(node, source).to_string());
                    if let Some(local) = identifier
                        && !local.is_empty()
                    {
                        binder.bindings.insert(
                            local,
                            ImportBinding {
                                module_specifier: module_specifier.clone(),
                                kind: ImportKind::Namespace,
                                imported_name: None,
                            },
                        );
                    }
                }
                "named_imports" => {
                    let mut spec_cursor = clause_child.walk();
                    for spec in clause_child.named_children(&mut spec_cursor) {
                        if spec.kind() != "import_specifier" {
                            continue;
                        }
                        let imported_name = spec
                            .child_by_field_name("name")
                            .map(|node| slice(node, source).to_string());
                        let alias = spec
                            .child_by_field_name("alias")
                            .map(|node| slice(node, source).to_string());
                        let local_name = alias
                            .clone()
                            .or_else(|| imported_name.clone())
                            .unwrap_or_default();
                        if local_name.is_empty() {
                            continue;
                        }
                        binder.bindings.insert(
                            local_name,
                            ImportBinding {
                                module_specifier: module_specifier.clone(),
                                kind: ImportKind::Named,
                                imported_name,
                            },
                        );
                    }
                }
                _ => {}
            }
        }
    }
}

fn unquote(text: &str) -> String {
    let trimmed = text.trim();
    let stripped = trimmed
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .or_else(|| {
            trimmed
                .strip_prefix('\'')
                .and_then(|value| value.strip_suffix('\''))
        });
    stripped.unwrap_or(trimmed).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tree_sitter::Parser;

    fn parse_javascript(source: &str) -> Tree {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_javascript::LANGUAGE.into())
            .expect("JavaScript grammar");
        parser.parse(source, None).expect("JavaScript tree")
    }

    fn find_node<'tree>(root: Node<'tree>, source: &str, text: &str) -> Node<'tree> {
        let mut stack = vec![root];
        while let Some(node) = stack.pop() {
            if slice(node, source) == text {
                return node;
            }
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                stack.push(child);
            }
        }
        panic!("missing node `{text}`");
    }

    #[test]
    fn static_member_receiver_rejects_private_property_segments() {
        let source = "class Box { #inner; read(other) { return other.#inner.value; } }";
        let tree = parse_javascript(source);
        let private_receiver = find_node(tree.root_node(), source, "other.#inner");

        assert_eq!("member_expression", private_receiver.kind());
        assert_eq!(
            "private_property_identifier",
            private_receiver
                .child_by_field_name("property")
                .expect("private property")
                .kind()
        );
        assert!(static_member_receiver(private_receiver, source).is_none());
    }
}
