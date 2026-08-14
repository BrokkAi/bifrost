use brokk_bifrost_core::analyzer::Range;
use brokk_bifrost_core::cancellation::CancellationToken;
use brokk_bifrost_core::hash::HashSet;
use tree_sitter::{Node, Tree};

#[derive(Debug, Default)]
pub struct PythonOverloadDecoratorBindings {
    direct: HashSet<String>,
    namespaces: HashSet<String>,
}

impl PythonOverloadDecoratorBindings {
    pub fn collect(root: Node<'_>, source: &str) -> Self {
        let mut bindings = Self::default();
        let mut stack = vec![root];

        while let Some(node) = stack.pop() {
            match node.kind() {
                "function_definition" | "class_definition" | "lambda" => continue,
                "import_statement" => bindings.collect_namespace_imports(node, source),
                "import_from_statement" => bindings.collect_direct_imports(node, source),
                _ => {}
            }

            let mut cursor = node.walk();
            let children: Vec<_> = node.named_children(&mut cursor).collect();
            stack.extend(children.into_iter().rev());
        }

        bindings
    }

    fn collect_namespace_imports(&mut self, node: Node<'_>, source: &str) {
        let mut cursor = node.walk();
        for imported in node.children_by_field_name("name", &mut cursor) {
            match imported.kind() {
                "dotted_name" => {
                    let module = node_text(imported, source).trim();
                    if is_typing_module(module) {
                        self.namespaces.insert(module.to_string());
                    }
                }
                "aliased_import" => {
                    let Some(name) = imported.child_by_field_name("name") else {
                        continue;
                    };
                    if !is_typing_module(node_text(name, source).trim()) {
                        continue;
                    }
                    let Some(alias) = imported.child_by_field_name("alias") else {
                        continue;
                    };
                    let alias = node_text(alias, source).trim();
                    if !alias.is_empty() {
                        self.namespaces.insert(alias.to_string());
                    }
                }
                _ => {}
            }
        }
    }

    fn collect_direct_imports(&mut self, node: Node<'_>, source: &str) {
        let Some(module) = node.child_by_field_name("module_name") else {
            return;
        };
        if !is_typing_module(node_text(module, source).trim()) {
            return;
        }

        let mut cursor = node.walk();
        for imported in node.children_by_field_name("name", &mut cursor) {
            match imported.kind() {
                "dotted_name" if node_text(imported, source).trim() == "overload" => {
                    self.direct.insert("overload".to_string());
                }
                "aliased_import" => {
                    let Some(name) = imported.child_by_field_name("name") else {
                        continue;
                    };
                    if node_text(name, source).trim() != "overload" {
                        continue;
                    }
                    let Some(alias) = imported.child_by_field_name("alias") else {
                        continue;
                    };
                    let alias = node_text(alias, source).trim();
                    if !alias.is_empty() {
                        self.direct.insert(alias.to_string());
                    }
                }
                _ => {}
            }
        }
    }

    pub fn decorates_as_overload(&self, function: Node<'_>, source: &str) -> bool {
        let Some(parent) = function
            .parent()
            .filter(|node| node.kind() == "decorated_definition")
        else {
            return false;
        };

        let mut cursor = parent.walk();
        parent
            .named_children(&mut cursor)
            .filter(|child| child.kind() == "decorator")
            .filter_map(decorator_callee)
            .any(|callee| match callee.kind() {
                "identifier" => self.direct.contains(node_text(callee, source).trim()),
                "attribute" => {
                    let Some(attribute) = callee.child_by_field_name("attribute") else {
                        return false;
                    };
                    if node_text(attribute, source).trim() != "overload" {
                        return false;
                    }
                    let Some(object) = callee.child_by_field_name("object") else {
                        return false;
                    };
                    object.kind() == "identifier"
                        && self.namespaces.contains(node_text(object, source).trim())
                }
                _ => false,
            })
    }
}

fn is_typing_module(module: &str) -> bool {
    matches!(module, "typing" | "typing_extensions")
}

fn node_text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    brokk_bifrost_core::analyzer::common::node_source_text(node, source)
}

/// Return the name-bearing node of a Python expression using tree-sitter fields.
pub fn expression_name_node<'tree>(expression: Node<'tree>) -> Option<Node<'tree>> {
    let mut current = expression;
    loop {
        match current.kind() {
            "identifier" => return Some(current),
            "attribute" => current = current.child_by_field_name("attribute")?,
            "call" => current = current.child_by_field_name("function")?,
            _ => return None,
        }
    }
}

/// Return a decorator's callable expression, peeling an optional invocation.
pub fn decorator_callee<'tree>(decorator: Node<'tree>) -> Option<Node<'tree>> {
    if decorator.kind() != "decorator" {
        return None;
    }
    let mut expression = decorator.named_child(0)?;
    while expression.kind() == "call" {
        expression = expression.child_by_field_name("function")?;
    }
    Some(expression)
}

/// Whether `node` is contained by a parser field that Python evaluates as an
/// annotation rather than as an ordinary expression.
pub fn python_node_is_in_annotation(node: Node<'_>) -> bool {
    let start = node.start_byte();
    let end = node.end_byte();
    let mut current = node;
    while let Some(parent) = current.parent() {
        let annotation = match parent.kind() {
            "function_definition" => parent.child_by_field_name("return_type"),
            "typed_parameter" | "typed_default_parameter" | "assignment" => {
                parent.child_by_field_name("type")
            }
            _ => None,
        };
        if let Some(annotation) = annotation
            && annotation.start_byte() <= start
            && end <= annotation.end_byte()
        {
            return true;
        }
        current = parent;
    }
    false
}

/// Parse one exactly mapped deferred annotation and return its identifier ranges.
pub fn python_deferred_annotation_identifier_ranges(
    string: Node<'_>,
    source: &str,
    cancellation: Option<&CancellationToken>,
) -> Option<Vec<Range>> {
    let tree = python_deferred_annotation_tree(string, source, cancellation)?;

    let mut ranges = Vec::new();
    let mut stack = vec![tree.root_node()];
    while let Some(current) = stack.pop() {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return None;
        }
        if current.kind() == "identifier" {
            ranges.push(Range {
                start_byte: current.start_byte(),
                end_byte: current.end_byte(),
                start_line: current.start_position().row + 1,
                end_line: current.end_position().row + 1,
            });
        }
        for index in (0..current.named_child_count()).rev() {
            if let Some(child) = current.named_child(index) {
                stack.push(child);
            }
        }
    }
    Some(ranges)
}

/// Parse one quoted annotation expression while preserving its original source
/// byte coordinates. Literal string values and arbitrary strings are rejected
/// by the same structured gate used by inverse membership.
pub fn python_deferred_annotation_tree(
    string: Node<'_>,
    source: &str,
    cancellation: Option<&CancellationToken>,
) -> Option<Tree> {
    if string.kind() != "string"
        || string
            .parent()
            .is_some_and(|parent| parent.kind() == "concatenated_string")
        || !python_node_is_in_annotation(string)
        || python_string_is_literal_value(string, source)
    {
        return None;
    }

    let mut content = None;
    for index in 0..string.named_child_count() {
        let child = string.named_child(index)?;
        match child.kind() {
            "string_start" | "string_end" => {}
            "string_content" if content.is_none() => content = Some(child),
            _ => return None,
        }
    }
    let content = content?;
    let language = tree_sitter_python::LANGUAGE.into();
    let tree = brokk_bifrost_core::analyzer::common::parse_source_range_with_cancellation(
        &language,
        source,
        content.range(),
        cancellation,
    )?;
    if tree.root_node().has_error() {
        return None;
    }
    Some(tree)
}

/// Whether `string` is a value argument of `Literal[...]`, rather than a
/// deferred type expression merely because the whole subscript is an
/// annotation.
fn python_string_is_literal_value(string: Node<'_>, source: &str) -> bool {
    let start = string.start_byte();
    let end = string.end_byte();
    let mut current = string;
    while let Some(parent) = current.parent() {
        match parent.kind() {
            "subscript" => {
                let Some(value) = parent.child_by_field_name("value") else {
                    return false;
                };
                if value.start_byte() <= start && end <= value.end_byte() {
                    return false;
                }
                return python_literal_annotation_base(value, source);
            }
            "generic_type" => {
                let Some(value) = parent.named_child(0) else {
                    return false;
                };
                return python_literal_annotation_base(value, source);
            }
            _ => current = parent,
        }
    }
    false
}

fn python_literal_annotation_base(value: Node<'_>, source: &str) -> bool {
    match value.kind() {
        "identifier" => node_text(value, source) == "Literal",
        "attribute" => {
            let (Some(object), Some(attribute)) = (
                value.child_by_field_name("object"),
                value.child_by_field_name("attribute"),
            ) else {
                return false;
            };
            object.kind() == "identifier"
                && matches!(node_text(object, source), "typing" | "typing_extensions")
                && attribute.kind() == "identifier"
                && node_text(attribute, source) == "Literal"
        }
        "member_type" => {
            let mut identifiers = Vec::new();
            let mut stack = vec![value];
            while let Some(node) = stack.pop() {
                if node.kind() == "identifier" {
                    identifiers.push(node_text(node, source));
                    continue;
                }
                for index in (0..node.named_child_count()).rev() {
                    if let Some(child) = node.named_child(index) {
                        stack.push(child);
                    }
                }
            }
            matches!(
                identifiers.as_slice(),
                ["typing", "Literal"] | ["typing_extensions", "Literal"]
            )
        }
        _ => false,
    }
}
