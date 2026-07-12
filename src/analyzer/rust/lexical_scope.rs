use crate::analyzer::ImportInfo;
use crate::analyzer::usages::{ImportBinder, ImportBinding, ImportKind};
use crate::hash::HashSet;
use tree_sitter::{Node, Parser};

use super::imports::{
    rust_import_body, rust_imports_from_use_declaration, split_rust_import_module_and_name,
};

pub(crate) fn parse_rust_tree(source: &str) -> Option<tree_sitter::Tree> {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_rust::LANGUAGE.into())
        .ok()?;
    parser.parse(source, None)
}

pub(crate) fn insert_rust_import_binding(binder: &mut ImportBinder, import: &ImportInfo) {
    let raw = import.raw_snippet.trim();
    if raw.ends_with("::*;") {
        let module_specifier = rust_import_body(raw)
            .and_then(|body| body.strip_suffix("::*"))
            .unwrap_or_default()
            .trim()
            .to_string();
        if module_specifier.is_empty() {
            return;
        }
        binder.bindings.insert(
            format!("*:{module_specifier}"),
            ImportBinding {
                module_specifier,
                kind: ImportKind::Glob,
                imported_name: None,
            },
        );
        return;
    }
    let Some((module_specifier, imported_name)) =
        split_rust_import_module_and_name(&import.raw_snippet)
    else {
        return;
    };
    let local_name = import
        .alias
        .clone()
        .or_else(|| import.identifier.clone())
        .unwrap_or_else(|| imported_name.clone());
    let (local_name, kind, imported_name, module_specifier) = if imported_name == "self" {
        let namespace_name = module_specifier
            .rsplit("::")
            .next()
            .unwrap_or(module_specifier.as_str())
            .to_string();
        (
            namespace_name,
            ImportKind::Namespace,
            None,
            module_specifier,
        )
    } else if !raw.contains('{')
        && imported_name
            .chars()
            .all(|ch| ch.is_ascii_lowercase() || ch == '_')
    {
        (
            imported_name.clone(),
            ImportKind::Namespace,
            None,
            format!("{module_specifier}::{imported_name}"),
        )
    } else {
        (
            local_name,
            ImportKind::Named,
            Some(imported_name),
            module_specifier,
        )
    };

    binder.bindings.insert(
        local_name,
        ImportBinding {
            module_specifier,
            kind,
            imported_name,
        },
    );
}

pub(crate) fn visible_import_binder_at(source: &str, reference_byte: usize) -> ImportBinder {
    let mut binder = ImportBinder::empty();
    let Some(tree) = parse_rust_tree(source) else {
        return binder;
    };
    let mut imports = Vec::new();
    collect_visible_use_statements(tree.root_node(), reference_byte, &mut imports);
    for import in imports
        .into_iter()
        .flat_map(|node| rust_imports_from_use_declaration(node, source))
    {
        insert_rust_import_binding(&mut binder, &import);
    }
    binder
}

fn collect_visible_use_statements<'tree>(
    node: Node<'tree>,
    reference_byte: usize,
    out: &mut Vec<Node<'tree>>,
) {
    if node.kind() == "use_declaration" {
        if use_statement_visible_at(node, reference_byte) {
            out.push(node);
        }
        return;
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.start_byte() <= reference_byte || child.end_byte() >= reference_byte {
            collect_visible_use_statements(child, reference_byte, out);
        }
    }
}

fn use_statement_visible_at(node: Node<'_>, reference_byte: usize) -> bool {
    if enclosing_mod_item_range(node)
        != enclosing_mod_item_range_at(root_node(node), reference_byte)
    {
        return false;
    }
    let Some((start, end)) = enclosing_visibility_scope_range(node) else {
        return true;
    };
    start <= reference_byte && reference_byte < end
}

fn root_node(mut node: Node<'_>) -> Node<'_> {
    while let Some(parent) = node.parent() {
        node = parent;
    }
    node
}

fn enclosing_mod_item_range(node: Node<'_>) -> Option<(usize, usize)> {
    let mut current = node.parent();
    while let Some(parent) = current {
        if parent.kind() == "mod_item" {
            return Some((parent.start_byte(), parent.end_byte()));
        }
        current = parent.parent();
    }
    None
}

pub(crate) fn enclosing_mod_item_range_at(node: Node<'_>, byte: usize) -> Option<(usize, usize)> {
    let mut candidate = None;
    let mut current = node;
    loop {
        let mut cursor = current.walk();
        let mut next = None;
        for child in current.named_children(&mut cursor) {
            if child.start_byte() <= byte && byte < child.end_byte() {
                if child.kind() == "mod_item" {
                    candidate = Some((child.start_byte(), child.end_byte()));
                }
                next = Some(child);
                break;
            }
        }
        let Some(child) = next else {
            return candidate;
        };
        current = child;
    }
}

pub(crate) fn enclosing_visibility_scope_range(node: Node<'_>) -> Option<(usize, usize)> {
    let mut current = node.parent();
    while let Some(parent) = current {
        if lexical_scope_kind(parent.kind()) {
            return Some((parent.start_byte(), parent.end_byte()));
        }
        current = parent.parent();
    }
    None
}

fn lexical_scope_kind(kind: &str) -> bool {
    matches!(
        kind,
        "block" | "function_item" | "impl_item" | "trait_item" | "mod_item"
    )
}

pub(crate) fn name_shadowed_at(source: &str, name: &str, reference_byte: usize) -> bool {
    let Some(tree) = parse_rust_tree(source) else {
        return false;
    };
    name_shadowed_in_tree(tree.root_node(), source, name, reference_byte)
}

pub(crate) fn name_shadowed_in_tree(
    root: Node<'_>,
    source: &str,
    name: &str,
    reference_byte: usize,
) -> bool {
    let Some(scope) = enclosing_function_or_closure(root, reference_byte) else {
        return false;
    };
    let mut bindings = HashSet::default();
    if let Some(params) = scope.child_by_field_name("parameters") {
        collect_parameter_bindings(params, source, &mut bindings);
    }
    if let Some(body) = scope.child_by_field_name("body") {
        collect_visible_local_bindings(body, source, reference_byte, &mut bindings);
    }
    collect_visible_let_condition_bindings(scope, source, reference_byte, &mut bindings);
    bindings.contains(name)
}

pub(crate) fn local_item_name_shadowed_in_tree(
    root: Node<'_>,
    source: &str,
    name: &str,
    reference_byte: usize,
) -> bool {
    let Some(scope) = enclosing_function_or_closure(root, reference_byte) else {
        return false;
    };
    let Some(body) = scope.child_by_field_name("body") else {
        return false;
    };
    let mut items = HashSet::default();
    collect_visible_local_items(body, source, reference_byte, &mut items);
    items.contains(name)
}

fn collect_visible_local_items(
    mut scope: Node<'_>,
    source: &str,
    reference_byte: usize,
    out: &mut HashSet<String>,
) {
    loop {
        let mut cursor = scope.walk();
        for node in scope.named_children(&mut cursor) {
            if matches!(
                node.kind(),
                "struct_item" | "enum_item" | "trait_item" | "type_item" | "function_item"
            ) {
                collect_local_item_name(node, source, out);
            }
        }
        let Some(child_scope) = child_lexical_scope_containing_reference(scope, reference_byte)
        else {
            return;
        };
        scope = child_scope;
    }
}

/// Whether `node` is the identifier being introduced by a Rust binding pattern.
/// Type/variant owners in structured patterns are deliberately excluded.
pub(crate) fn is_pattern_binding_identifier(node: Node<'_>) -> bool {
    if node.kind() != "identifier" {
        return false;
    }
    let mut current = node.parent();
    while let Some(parent) = current {
        if matches!(
            parent.kind(),
            "let_declaration" | "let_condition" | "parameter" | "match_arm" | "for_expression"
        ) && let Some(pattern) = parent.child_by_field_name("pattern")
            && pattern_contains_binding_identifier(pattern, node)
        {
            return true;
        }
        if parent.kind() == "closure_parameters"
            && pattern_contains_binding_identifier(parent, node)
        {
            return true;
        }
        if matches!(
            parent.kind(),
            "block" | "function_item" | "closure_expression"
        ) {
            return false;
        }
        current = parent.parent();
    }
    false
}

fn pattern_contains_binding_identifier(pattern: Node<'_>, target: Node<'_>) -> bool {
    let mut stack = vec![pattern];
    while let Some(node) = stack.pop() {
        match node.kind() {
            "identifier" => {
                if node.id() == target.id() {
                    return true;
                }
            }
            "field_pattern" => {
                if let Some(pattern) = node.child_by_field_name("pattern") {
                    stack.push(pattern);
                } else if let Some(name) = node.child_by_field_name("name") {
                    stack.push(name);
                }
            }
            "struct_pattern" => {
                let mut cursor = node.walk();
                stack.extend(node.named_children(&mut cursor).filter(|child| {
                    matches!(
                        child.kind(),
                        "field_pattern"
                            | "remaining_field_pattern"
                            | "tuple_pattern"
                            | "struct_pattern"
                            | "ref_pattern"
                            | "mut_pattern"
                    )
                }));
            }
            "tuple_struct_pattern" => {
                let type_id = node.child_by_field_name("type").map(|ty| ty.id());
                let mut cursor = node.walk();
                stack.extend(node.named_children(&mut cursor).filter(|child| {
                    Some(child.id()) != type_id
                        && matches!(
                            child.kind(),
                            "identifier"
                                | "tuple_pattern"
                                | "tuple_struct_pattern"
                                | "struct_pattern"
                                | "ref_pattern"
                                | "mut_pattern"
                        )
                }));
            }
            _ => {
                let mut cursor = node.walk();
                stack.extend(node.named_children(&mut cursor));
            }
        }
    }
    false
}

fn enclosing_function_or_closure(root: Node<'_>, reference_byte: usize) -> Option<Node<'_>> {
    let mut best = None;
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.start_byte() <= reference_byte && reference_byte < node.end_byte() {
            if matches!(node.kind(), "function_item" | "closure_expression") {
                best = Some(node);
            }
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                stack.push(child);
            }
        }
    }
    best
}

fn collect_parameter_bindings(node: Node<'_>, source: &str, out: &mut HashSet<String>) {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        match child.kind() {
            "self_parameter" => {}
            "parameter" => {
                if let Some(pattern) = child.child_by_field_name("pattern") {
                    collect_pattern_bindings(pattern, source, out);
                }
            }
            _ => collect_pattern_bindings(child, source, out),
        }
    }
}

fn collect_visible_local_bindings(
    mut scope: Node<'_>,
    source: &str,
    reference_byte: usize,
    out: &mut HashSet<String>,
) {
    loop {
        collect_direct_bindings_in_scope(scope, source, reference_byte, out);
        let Some(child_scope) = child_lexical_scope_containing_reference(scope, reference_byte)
        else {
            return;
        };
        scope = child_scope;
    }
}

fn collect_visible_let_condition_bindings(
    root: Node<'_>,
    source: &str,
    reference_byte: usize,
    out: &mut HashSet<String>,
) {
    let mut current = root;
    loop {
        if matches!(current.kind(), "if_expression" | "while_expression")
            && let Some(condition) = current.child_by_field_name("condition")
        {
            let body = current
                .child_by_field_name("consequence")
                .or_else(|| current.child_by_field_name("body"));
            if contains_byte(condition, reference_byte)
                || body.is_some_and(|body| contains_byte(body, reference_byte))
            {
                collect_let_condition_bindings_before(condition, source, reference_byte, out);
            }
        }

        let mut cursor = current.walk();
        let mut next = None;
        for child in current.named_children(&mut cursor) {
            if contains_byte(child, reference_byte) {
                next = Some(child);
                break;
            }
        }
        let Some(child) = next else {
            return;
        };
        current = child;
    }
}

fn collect_let_condition_bindings_before(
    condition: Node<'_>,
    source: &str,
    reference_byte: usize,
    out: &mut HashSet<String>,
) {
    let mut stack = vec![condition];
    while let Some(node) = stack.pop() {
        match node.kind() {
            "let_condition" => {
                if node.end_byte() <= reference_byte
                    && let Some(pattern) = node.child_by_field_name("pattern")
                {
                    collect_pattern_bindings(pattern, source, out);
                }
            }
            "let_chain" => {
                let mut cursor = node.walk();
                let children: Vec<_> = node.named_children(&mut cursor).collect();
                stack.extend(
                    children
                        .into_iter()
                        .rev()
                        .filter(|child| matches!(child.kind(), "let_condition" | "let_chain")),
                );
            }
            _ => {}
        }
    }
}

fn contains_byte(node: Node<'_>, byte: usize) -> bool {
    node.start_byte() <= byte && byte < node.end_byte()
}

fn collect_direct_bindings_in_scope(
    scope: Node<'_>,
    source: &str,
    reference_byte: usize,
    out: &mut HashSet<String>,
) {
    let mut cursor = scope.walk();
    for node in scope.named_children(&mut cursor) {
        match node.kind() {
            "let_declaration" => {
                if node.end_byte() <= reference_byte
                    && let Some(pattern) = node.child_by_field_name("pattern")
                {
                    collect_pattern_bindings(pattern, source, out);
                }
            }
            "struct_item" | "enum_item" | "trait_item" | "type_item" | "function_item" => {
                collect_local_item_name(node, source, out)
            }
            _ => {}
        }
    }
}

fn child_lexical_scope_containing_reference(
    mut node: Node<'_>,
    reference_byte: usize,
) -> Option<Node<'_>> {
    loop {
        let mut cursor = node.walk();
        let mut next = None;
        for child in node.named_children(&mut cursor) {
            if contains_byte(child, reference_byte) {
                if lexical_scope_kind(child.kind()) {
                    return Some(child);
                }
                next = Some(child);
                break;
            }
        }
        node = next?;
    }
}

fn collect_local_item_name(node: Node<'_>, source: &str, out: &mut HashSet<String>) {
    if let Some(name) = node.child_by_field_name("name") {
        let text = node_text(name, source).trim();
        if !text.is_empty() {
            out.insert(text.to_string());
        }
    }
}

fn collect_pattern_bindings(node: Node<'_>, source: &str, out: &mut HashSet<String>) {
    let mut stack = vec![node];
    while let Some(node) = stack.pop() {
        match node.kind() {
            "identifier" => {
                let text = node_text(node, source).trim();
                if !text.is_empty() {
                    out.insert(text.to_string());
                }
            }
            "field_pattern" => {
                if let Some(pattern) = node.child_by_field_name("pattern") {
                    stack.push(pattern);
                } else if let Some(name) = node.child_by_field_name("name") {
                    let text = node_text(name, source).trim();
                    if !text.is_empty() {
                        out.insert(text.to_string());
                    }
                }
            }
            "struct_pattern" => {
                let mut cursor = node.walk();
                stack.extend(node.named_children(&mut cursor).filter(|child| {
                    matches!(
                        child.kind(),
                        "field_pattern"
                            | "remaining_field_pattern"
                            | "tuple_pattern"
                            | "struct_pattern"
                            | "ref_pattern"
                            | "mut_pattern"
                    )
                }));
            }
            "tuple_struct_pattern" => {
                let type_id = node.child_by_field_name("type").map(|ty| ty.id());
                let mut cursor = node.walk();
                stack.extend(node.named_children(&mut cursor).filter(|child| {
                    Some(child.id()) != type_id
                        && matches!(
                            child.kind(),
                            "identifier"
                                | "tuple_pattern"
                                | "tuple_struct_pattern"
                                | "struct_pattern"
                                | "ref_pattern"
                                | "mut_pattern"
                        )
                }));
            }
            _ => {
                let mut cursor = node.walk();
                stack.extend(node.named_children(&mut cursor));
            }
        }
    }
}

fn node_text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    source
        .get(node.start_byte()..node.end_byte())
        .unwrap_or_default()
}
