use crate::analyzer::ImportInfo;
use crate::analyzer::usages::{ImportBinder, ImportBinding, ImportKind};
use crate::hash::{HashMap, HashSet};
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
            local_name,
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
    let Some(tree) = parse_rust_tree(source) else {
        return ImportBinder::empty();
    };
    visible_import_binder_in_tree(tree.root_node(), source, reference_byte)
}

pub(crate) fn visible_import_binder_in_tree(
    root: Node<'_>,
    source: &str,
    reference_byte: usize,
) -> ImportBinder {
    let mut binder = ImportBinder::empty();
    let mut imports = Vec::new();
    collect_visible_use_statements(root, reference_byte, &mut imports);
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
    RustLexicalScopeIndex::new(root, source).name_bound_at(name, reference_byte)
}

#[derive(Clone, Copy)]
struct BindingVisibility {
    start: usize,
    end: usize,
    function: Option<(usize, usize)>,
}

#[derive(Clone, Copy)]
struct ItemVisibility {
    start: usize,
    end: usize,
    module: Option<(usize, usize)>,
}

/// Position-aware Rust binding visibility for one parsed file.
pub(crate) struct RustLexicalScopeIndex {
    bindings: HashMap<String, Vec<BindingVisibility>>,
    items: HashMap<String, Vec<ItemVisibility>>,
    modules: Vec<(usize, usize)>,
    functions: Vec<(usize, usize)>,
}

impl RustLexicalScopeIndex {
    pub(crate) fn new(root: Node<'_>, source: &str) -> Self {
        let mut index = Self {
            bindings: HashMap::default(),
            items: HashMap::default(),
            modules: Vec::new(),
            functions: Vec::new(),
        };
        let mut stack = vec![(root, None, root.start_byte(), root.end_byte())];
        while let Some((node, function, scope_start, scope_end)) = stack.pop() {
            let mut child_function = function;
            let mut child_scope_start = scope_start;
            let mut child_scope_end = scope_end;
            match node.kind() {
                "function_item" => {
                    index.add_item_binding(node, scope_start, scope_end, source);
                    let function_range = (node.start_byte(), node.end_byte());
                    index.functions.push(function_range);
                    child_function = Some(function_range);
                    if let Some(body) = node.child_by_field_name("body") {
                        child_scope_end = body.end_byte();
                        index.add_parameter_bindings(node, body, source, child_function);
                    }
                }
                "closure_expression" => {
                    if let Some(body) = node.child_by_field_name("body") {
                        index.add_parameter_bindings(node, body, source, function);
                    }
                }
                "block" | "declaration_list" => {
                    child_scope_start = node.start_byte();
                    child_scope_end = node.end_byte();
                }
                "let_declaration" => {
                    if let Some(pattern) = node.child_by_field_name("pattern") {
                        index.add_pattern_bindings(
                            pattern,
                            node.end_byte(),
                            scope_end,
                            source,
                            function,
                        );
                    }
                }
                "let_condition" => {
                    if let Some(pattern) = node.child_by_field_name("pattern")
                        && let Some(end) = let_condition_visibility_end(node)
                    {
                        index.add_pattern_bindings(pattern, node.end_byte(), end, source, function);
                    }
                }
                "match_arm" => {
                    if let Some(pattern) = node.child_by_field_name("pattern") {
                        index.add_pattern_bindings(
                            pattern,
                            pattern.end_byte(),
                            node.end_byte(),
                            source,
                            function,
                        );
                    }
                }
                "for_expression" => {
                    if let (Some(pattern), Some(body)) = (
                        node.child_by_field_name("pattern"),
                        node.child_by_field_name("body"),
                    ) {
                        index.add_pattern_bindings(
                            pattern,
                            body.start_byte(),
                            body.end_byte(),
                            source,
                            function,
                        );
                    }
                }
                "type_item" if !is_associated_type_item(node) => {
                    index.add_item_binding(node, scope_start, scope_end, source);
                }
                "struct_item" | "enum_item" | "trait_item" | "mod_item" => {
                    index.add_item_binding(node, scope_start, scope_end, source);
                    if node.kind() == "mod_item" {
                        index.modules.push((node.start_byte(), node.end_byte()));
                    }
                }
                _ => {}
            }

            let mut cursor = node.walk();
            let children: Vec<_> = node.named_children(&mut cursor).collect();
            stack.extend(
                children
                    .into_iter()
                    .rev()
                    .map(|child| (child, child_function, child_scope_start, child_scope_end)),
            );
        }
        index
    }

    pub(crate) fn name_bound_at(&self, name: &str, byte: usize) -> bool {
        self.visibility_contains(&self.bindings, name, byte)
    }

    pub(crate) fn item_bound_at(&self, name: &str, byte: usize) -> bool {
        let module = self
            .modules
            .iter()
            .copied()
            .filter(|(start, end)| *start <= byte && byte < *end)
            .min_by_key(|(start, end)| end - start);
        self.items.get(name).is_some_and(|items| {
            items
                .iter()
                .any(|item| item.module == module && item.start <= byte && byte < item.end)
        })
    }

    fn visibility_contains(
        &self,
        entries: &HashMap<String, Vec<BindingVisibility>>,
        name: &str,
        byte: usize,
    ) -> bool {
        let function = self
            .functions
            .iter()
            .copied()
            .filter(|(start, end)| *start <= byte && byte < *end)
            .min_by_key(|(start, end)| end - start);
        entries.get(name).is_some_and(|bindings| {
            bindings.iter().any(|binding| {
                binding.function == function && binding.start <= byte && byte < binding.end
            })
        })
    }

    fn add_parameter_bindings(
        &mut self,
        node: Node<'_>,
        body: Node<'_>,
        source: &str,
        function: Option<(usize, usize)>,
    ) {
        let Some(parameters) = node.child_by_field_name("parameters") else {
            return;
        };
        let mut cursor = parameters.walk();
        for parameter in parameters.named_children(&mut cursor) {
            let pattern = parameter
                .child_by_field_name("pattern")
                .unwrap_or(parameter);
            self.add_pattern_bindings(
                pattern,
                body.start_byte(),
                body.end_byte(),
                source,
                function,
            );
        }
    }

    fn add_pattern_bindings(
        &mut self,
        pattern: Node<'_>,
        start: usize,
        end: usize,
        source: &str,
        function: Option<(usize, usize)>,
    ) {
        if start >= end {
            return;
        }
        let mut names = HashSet::default();
        collect_pattern_bindings(pattern, source, &mut names);
        for name in names {
            self.bindings
                .entry(name)
                .or_default()
                .push(BindingVisibility {
                    start,
                    end,
                    function,
                });
        }
    }

    fn add_item_binding(&mut self, item: Node<'_>, start: usize, end: usize, source: &str) {
        let Some(name) = item.child_by_field_name("name") else {
            return;
        };
        let name = node_text(name, source).trim();
        if name.is_empty() {
            return;
        }
        self.items
            .entry(name.to_string())
            .or_default()
            .push(ItemVisibility {
                start,
                end,
                module: enclosing_mod_item_range(item),
            });
    }
}

fn is_associated_type_item(mut node: Node<'_>) -> bool {
    while let Some(parent) = node.parent() {
        match parent.kind() {
            "impl_item" | "trait_item" => return true,
            "function_item" | "mod_item" | "source_file" => return false,
            _ => node = parent,
        }
    }
    false
}

fn let_condition_visibility_end(mut node: Node<'_>) -> Option<usize> {
    while let Some(parent) = node.parent() {
        if matches!(parent.kind(), "if_expression" | "while_expression") {
            return parent
                .child_by_field_name("consequence")
                .or_else(|| parent.child_by_field_name("body"))
                .map(|body| body.end_byte());
        }
        if !matches!(parent.kind(), "let_chain" | "parenthesized_expression") {
            return None;
        }
        node = parent;
    }
    None
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
    if !matches!(node.kind(), "identifier" | "shorthand_field_identifier") {
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
            "identifier" | "shorthand_field_identifier" => {
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

fn contains_byte(node: Node<'_>, byte: usize) -> bool {
    node.start_byte() <= byte && byte < node.end_byte()
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
