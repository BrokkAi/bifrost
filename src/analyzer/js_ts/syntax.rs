use crate::analyzer::js_ts::imports::{
    CommonJsRequireBindingKind, commonjs_require_module_specifier_from_declarator,
    parse_commonjs_require_bindings_from_node,
};
use crate::analyzer::usages::{ImportBinder, ImportBinding, ImportKind};
use tree_sitter::{Node, Tree};

pub(crate) fn slice<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    source.get(node.start_byte()..node.end_byte()).unwrap_or("")
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
