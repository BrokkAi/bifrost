use crate::hash::HashSet;
use tree_sitter::Node;

#[derive(Debug, Default)]
pub(super) struct PythonOverloadDecoratorBindings {
    direct: HashSet<String>,
    namespaces: HashSet<String>,
}

impl PythonOverloadDecoratorBindings {
    pub(super) fn collect(root: Node<'_>, source: &str) -> Self {
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

    pub(super) fn decorates_as_overload(&self, function: Node<'_>, source: &str) -> bool {
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
    crate::analyzer::common::node_source_text(node, source)
}

/// Return the name-bearing node of a Python expression using tree-sitter fields.
pub(super) fn expression_name_node<'tree>(expression: Node<'tree>) -> Option<Node<'tree>> {
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
pub(super) fn decorator_callee<'tree>(decorator: Node<'tree>) -> Option<Node<'tree>> {
    if decorator.kind() != "decorator" {
        return None;
    }
    let mut expression = decorator.named_child(0)?;
    while expression.kind() == "call" {
        expression = expression.child_by_field_name("function")?;
    }
    Some(expression)
}
