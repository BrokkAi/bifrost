use crate::analyzer::{CodeUnit, CodeUnitType, ProjectFile, Range};
use tree_sitter::{Node, Point, Tree};

pub(super) fn parse_php_file(
    file: &ProjectFile,
    source: &str,
    tree: &Tree,
) -> crate::analyzer::tree_sitter_analyzer::ParsedFile {
    let package_name = determine_php_package_name(tree.root_node(), source);
    let mut parsed = crate::analyzer::tree_sitter_analyzer::ParsedFile::new(package_name);
    let package_name = parsed.package_name.clone();
    let mut visitor = PhpVisitor {
        file,
        source,
        parsed: &mut parsed,
    };
    visitor.visit_children(tree.root_node(), &PhpScope::new(package_name, None));
    parsed
}

#[derive(Clone)]
struct PhpScope {
    package_name: String,
    class_unit: Option<CodeUnit>,
}

impl PhpScope {
    fn new(package_name: String, class_unit: Option<CodeUnit>) -> Self {
        Self {
            package_name,
            class_unit,
        }
    }
}

struct PhpContainer<'tree> {
    node: Node<'tree>,
    scope: PhpScope,
}

struct PhpNodeWork<'tree> {
    node: Node<'tree>,
    scope: PhpScope,
}

enum PhpWork<'tree> {
    Container(PhpContainer<'tree>),
    Node(PhpNodeWork<'tree>),
}

fn push_php_child_work<'tree>(node: Node<'tree>, scope: PhpScope, stack: &mut Vec<PhpWork<'tree>>) {
    for index in (0..node.named_child_count()).rev() {
        if let Some(child) = node.named_child(index) {
            stack.push(PhpWork::Node(PhpNodeWork {
                node: child,
                scope: scope.clone(),
            }));
        }
    }
}

struct PhpVisitor<'a> {
    file: &'a ProjectFile,
    source: &'a str,
    parsed: &'a mut crate::analyzer::tree_sitter_analyzer::ParsedFile,
}

impl<'a> PhpVisitor<'a> {
    fn visit_children(&mut self, node: Node<'_>, scope: &PhpScope) {
        let mut stack = vec![PhpWork::Container(PhpContainer {
            node,
            scope: PhpScope::new(scope.package_name.clone(), scope.class_unit.clone()),
        })];
        while let Some(work) = stack.pop() {
            match work {
                PhpWork::Container(container) => {
                    push_php_child_work(container.node, container.scope, &mut stack);
                }
                PhpWork::Node(work) => {
                    self.visit_node(work.node, &work.scope, &mut stack);
                }
            }
        }
    }

    fn visit_node<'tree>(
        &mut self,
        node: Node<'tree>,
        scope: &PhpScope,
        stack: &mut Vec<PhpWork<'tree>>,
    ) {
        match node.kind() {
            "namespace_definition" => self.visit_namespace(node, scope, stack),
            "class_declaration"
            | "interface_declaration"
            | "trait_declaration"
            | "enum_declaration" => self.visit_type_declaration(node, scope, stack),
            "function_definition" => self.visit_function(node, scope),
            "method_declaration" => self.visit_method(node, scope),
            "property_declaration" => self.visit_property_declaration(node, scope),
            "const_declaration" => self.visit_const_declaration(node, scope),
            "enum_case" => self.visit_enum_case(node, scope),
            "declaration_list" | "compound_statement" => {
                stack.push(PhpWork::Container(PhpContainer {
                    node,
                    scope: PhpScope::new(scope.package_name.clone(), scope.class_unit.clone()),
                }))
            }
            _ => {}
        }
    }

    fn visit_namespace<'tree>(
        &mut self,
        node: Node<'tree>,
        scope: &PhpScope,
        stack: &mut Vec<PhpWork<'tree>>,
    ) {
        let Some(name_node) = node.child_by_field_name("name") else {
            return;
        };
        let package_name = php_node_text(name_node, self.source).replace('\\', ".");
        let scope = PhpScope::new(package_name, scope.class_unit.clone());
        for index in (0..node.named_child_count()).rev() {
            let Some(child) = node.named_child(index) else {
                continue;
            };
            if !matches!(child.kind(), "namespace_name" | "name") {
                stack.push(PhpWork::Node(PhpNodeWork {
                    node: child,
                    scope: scope.clone(),
                }));
            }
        }
    }

    fn visit_type_declaration<'tree>(
        &mut self,
        node: Node<'tree>,
        scope: &PhpScope,
        stack: &mut Vec<PhpWork<'tree>>,
    ) {
        let Some(name_node) = node.child_by_field_name("name") else {
            return;
        };
        let name = php_node_text(name_node, self.source).trim().to_string();
        if name.is_empty() {
            return;
        }

        let short_name = if let Some(parent) = &scope.class_unit {
            format!("{}${name}", parent.short_name())
        } else {
            name
        };
        let code_unit = CodeUnit::new(
            self.file.clone(),
            CodeUnitType::Class,
            scope.package_name.clone(),
            short_name,
        );
        self.parsed.add_code_unit(
            code_unit.clone(),
            node,
            self.source,
            scope.class_unit.clone(),
            None,
        );
        self.parsed
            .set_primary_range(&code_unit, php_declaration_range(node, self.source));
        self.parsed
            .add_signature(code_unit.clone(), php_type_signature(node, self.source));
        self.parsed
            .set_raw_supertypes(code_unit.clone(), extract_php_supertypes(node, self.source));

        if let Some(body) = php_class_body(node) {
            stack.push(PhpWork::Container(PhpContainer {
                node: body,
                scope: PhpScope::new(scope.package_name.clone(), Some(code_unit)),
            }));
        }
    }

    fn visit_function(&mut self, node: Node<'_>, scope: &PhpScope) {
        let Some(name_node) = node.child_by_field_name("name") else {
            return;
        };
        let name = php_node_text(name_node, self.source).trim().to_string();
        if name.is_empty() {
            return;
        }
        let short_name = if let Some(parent) = &scope.class_unit {
            format!("{}.{}", parent.short_name(), name)
        } else {
            name
        };
        let code_unit = CodeUnit::new(
            self.file.clone(),
            CodeUnitType::Function,
            scope.package_name.clone(),
            short_name,
        );
        self.parsed.add_code_unit(
            code_unit.clone(),
            node,
            self.source,
            scope.class_unit.clone(),
            None,
        );
        self.parsed
            .set_primary_range(&code_unit, php_declaration_range(node, self.source));
        self.parsed
            .add_signature(code_unit, php_function_signature(node, self.source));
    }

    fn visit_method(&mut self, node: Node<'_>, scope: &PhpScope) {
        self.visit_function(node, scope);
        self.visit_promoted_parameters(node, scope);
    }

    fn visit_property_declaration(&mut self, node: Node<'_>, scope: &PhpScope) {
        let Some(parent) = &scope.class_unit else {
            return;
        };
        let modifiers = php_property_prefix(node, self.source);
        let type_prefix = node
            .child_by_field_name("type")
            .map(|type_node| format!("{} ", php_node_text(type_node, self.source).trim()))
            .unwrap_or_default();
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            if child.kind() != "property_element" {
                continue;
            }
            let Some(name_node) = child.child_by_field_name("name") else {
                continue;
            };
            let raw_name = php_node_text(name_node, self.source).trim().to_string();
            if raw_name.is_empty() {
                continue;
            }
            let stripped_name = raw_name.trim_start_matches('$');
            let code_unit = CodeUnit::new(
                self.file.clone(),
                CodeUnitType::Field,
                scope.package_name.clone(),
                format!("{}.{}", parent.short_name(), stripped_name),
            );
            self.parsed.add_code_unit(
                code_unit.clone(),
                node,
                self.source,
                Some(parent.clone()),
                None,
            );
            self.parsed
                .set_primary_range(&code_unit, php_declaration_range(node, self.source));
            let value = child
                .child_by_field_name("default_value")
                .filter(|value| php_is_literal(*value));
            let signature = if let Some(value) = value {
                format!(
                    "{modifiers}{type_prefix}{raw_name} = {};",
                    php_node_text(value, self.source).trim()
                )
            } else {
                format!("{modifiers}{type_prefix}{raw_name};")
            };
            self.parsed.add_signature(code_unit, signature);
        }
    }

    fn visit_const_declaration(&mut self, node: Node<'_>, scope: &PhpScope) {
        let prefix = php_const_prefix(node, self.source);
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            if child.kind() != "const_element" {
                continue;
            }
            let Some(name_node) = php_find_named_descendant(child, "name") else {
                continue;
            };
            let name = php_node_text(name_node, self.source).trim().to_string();
            if name.is_empty() {
                continue;
            }
            let short_name = if let Some(parent) = &scope.class_unit {
                format!("{}.{}", parent.short_name(), name)
            } else {
                format!("_module_.{name}")
            };
            let code_unit = CodeUnit::new(
                self.file.clone(),
                CodeUnitType::Field,
                scope.package_name.clone(),
                short_name,
            );
            self.parsed.add_code_unit(
                code_unit.clone(),
                node,
                self.source,
                scope.class_unit.clone(),
                None,
            );
            self.parsed
                .set_primary_range(&code_unit, php_declaration_range(node, self.source));
            let value = php_const_value(child).filter(|value| php_is_literal(*value));
            let signature = if let Some(value) = value {
                format!(
                    "{prefix}{name} = {};",
                    php_node_text(value, self.source).trim()
                )
            } else {
                format!("{prefix}{name};")
            };
            self.parsed.add_signature(code_unit, signature);
        }
    }

    fn visit_enum_case(&mut self, node: Node<'_>, scope: &PhpScope) {
        let Some(parent) = &scope.class_unit else {
            return;
        };
        let Some(name_node) = node.child_by_field_name("name") else {
            return;
        };
        let name = php_node_text(name_node, self.source).trim().to_string();
        if name.is_empty() {
            return;
        }
        let code_unit = CodeUnit::new(
            self.file.clone(),
            CodeUnitType::Field,
            scope.package_name.clone(),
            format!("{}.{}", parent.short_name(), name),
        );
        self.parsed.add_code_unit(
            code_unit.clone(),
            node,
            self.source,
            Some(parent.clone()),
            None,
        );
        self.parsed
            .set_primary_range(&code_unit, php_declaration_range(node, self.source));
        self.parsed.add_signature(
            code_unit,
            normalize_php_snippet(&php_node_text(node, self.source)),
        );
    }

    fn visit_promoted_parameters(&mut self, node: Node<'_>, scope: &PhpScope) {
        let Some(parent) = &scope.class_unit else {
            return;
        };
        let Some(parameters) = node.child_by_field_name("parameters") else {
            return;
        };
        let mut cursor = parameters.walk();
        for parameter in parameters.named_children(&mut cursor) {
            if parameter.kind() != "property_promotion_parameter" {
                continue;
            }
            let Some(name_node) = parameter.child_by_field_name("name") else {
                continue;
            };
            let raw_name = php_node_text(name_node, self.source).trim().to_string();
            if raw_name.is_empty() {
                continue;
            }
            let stripped_name = raw_name.trim_start_matches('$');
            let code_unit = CodeUnit::new(
                self.file.clone(),
                CodeUnitType::Field,
                scope.package_name.clone(),
                format!("{}.{}", parent.short_name(), stripped_name),
            );
            self.parsed.add_code_unit(
                code_unit.clone(),
                parameter,
                self.source,
                Some(parent.clone()),
                None,
            );
            self.parsed
                .set_primary_range(&code_unit, php_declaration_range(parameter, self.source));
            let signature = format!(
                "{};",
                normalize_php_snippet(&php_node_text(parameter, self.source)).trim_end_matches(',')
            );
            self.parsed.add_signature(code_unit, signature);
        }
    }
}

fn determine_php_package_name(root: Node<'_>, source: &str) -> String {
    let mut cursor = root.walk();
    for child in root.named_children(&mut cursor) {
        if child.kind() != "namespace_definition" {
            continue;
        }
        if let Some(name_node) = child.child_by_field_name("name") {
            return php_node_text(name_node, source).replace('\\', ".");
        }
    }
    String::new()
}

fn php_class_body(node: Node<'_>) -> Option<Node<'_>> {
    node.child_by_field_name("body").or_else(|| {
        let mut cursor = node.walk();
        node.named_children(&mut cursor)
            .find(|child| child.kind() == "declaration_list")
    })
}

fn php_type_signature(node: Node<'_>, source: &str) -> String {
    let declaration_text = php_raw_text_with_attributes(node, source);
    let trimmed = normalize_php_snippet(&declaration_text);
    let Some((head, _)) = trimmed.split_once('{') else {
        return trimmed.to_string();
    };
    format!("{} {{", head.trim_end())
}

fn extract_php_supertypes(node: Node<'_>, source: &str) -> Vec<String> {
    let mut raw = Vec::new();
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if matches!(child.kind(), "base_clause" | "class_interface_clause") {
            collect_php_supertype_nodes(child, source, &mut raw);
        }
    }
    raw
}

fn collect_php_supertype_nodes(node: Node<'_>, source: &str, raw: &mut Vec<String>) {
    let mut stack = vec![node];
    while let Some(current) = stack.pop() {
        if matches!(
            current.kind(),
            "name" | "namespace_name" | "qualified_name" | "fully_qualified_name"
        ) {
            let text = php_node_text(current, source);
            let text = text.trim();
            if !text.is_empty() {
                raw.push(text.to_string());
            }
            continue;
        }

        for index in (0..current.named_child_count()).rev() {
            if let Some(child) = current.named_child(index) {
                stack.push(child);
            }
        }
    }
}

fn php_function_signature(node: Node<'_>, source: &str) -> String {
    let declaration_range = php_declaration_range(node, source);
    if let Some(body) = node.child_by_field_name("body") {
        let header =
            normalize_php_snippet(&source[declaration_range.start_byte..body.start_byte()]);
        format!("{header} {{ ... }}")
    } else {
        php_text_with_attributes(node, source).trim().to_string()
    }
}

fn php_property_prefix(node: Node<'_>, source: &str) -> String {
    let mut parts = php_attribute_lines(node, source);
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        match child.kind() {
            "visibility_modifier"
            | "static_modifier"
            | "readonly_modifier"
            | "abstract_modifier"
            | "final_modifier" => parts.push(php_node_text(child, source).trim().to_string()),
            _ => {}
        }
    }
    if parts.is_empty() {
        String::new()
    } else {
        format!("{} ", parts.join(" "))
    }
}

fn php_const_prefix(node: Node<'_>, source: &str) -> String {
    let mut parts = php_attribute_lines(node, source);
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        match child.kind() {
            "visibility_modifier"
            | "static_modifier"
            | "readonly_modifier"
            | "abstract_modifier"
            | "final_modifier" => parts.push(php_node_text(child, source).trim().to_string()),
            _ => {}
        }
    }
    parts.push("const".to_string());
    format!("{} ", parts.join(" "))
}

fn php_attribute_lines(node: Node<'_>, source: &str) -> Vec<String> {
    let mut attributes = Vec::new();
    let mut current = node;
    while let Some(prev) = current.prev_named_sibling() {
        if prev.kind() != "attribute_list" {
            break;
        }
        let gap = &source[prev.end_byte()..current.start_byte()];
        if !gap.trim().is_empty() {
            break;
        }
        attributes.push(php_node_text(prev, source).trim().to_string());
        current = prev;
    }
    attributes.reverse();
    attributes
}

fn php_text_with_attributes(node: Node<'_>, source: &str) -> String {
    normalize_php_snippet(&php_raw_text_with_attributes(node, source))
}

fn php_raw_text_with_attributes(node: Node<'_>, source: &str) -> String {
    let range = php_declaration_range(node, source);
    source[range.start_byte..range.end_byte].to_string()
}

fn php_declaration_range(node: Node<'_>, source: &str) -> Range {
    let mut start_byte = node.start_byte();
    let mut start_point = node.start_position();
    let mut current = node;
    while let Some(prev) = current.prev_named_sibling() {
        if prev.kind() != "attribute_list" {
            break;
        }
        let gap = &source[prev.end_byte()..current.start_byte()];
        if !gap.trim().is_empty() {
            break;
        }
        start_byte = prev.start_byte();
        start_point = prev.start_position();
        current = prev;
    }
    php_range(
        start_byte,
        start_point,
        node.end_byte(),
        node.end_position(),
    )
}

fn php_is_literal(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "integer"
            | "float"
            | "string"
            | "encapsed_string"
            | "string_value"
            | "boolean"
            | "boolean_literal"
            | "null"
            | "null_literal"
    )
}

fn php_node_text(node: Node<'_>, source: &str) -> String {
    source[node.start_byte()..node.end_byte()].to_string()
}

fn php_const_value(node: Node<'_>) -> Option<Node<'_>> {
    node.child_by_field_name("value").or_else(|| {
        let mut cursor = node.walk();
        node.named_children(&mut cursor)
            .filter(|child| child.kind() != "name")
            .find(|child| child.kind() != "comment")
    })
}

fn php_find_named_descendant<'a>(node: Node<'a>, kind: &str) -> Option<Node<'a>> {
    let mut stack = vec![node];
    while let Some(node) = stack.pop() {
        if node.kind() == kind {
            return Some(node);
        }
        let mut cursor = node.walk();
        let children = node.named_children(&mut cursor).collect::<Vec<_>>();
        stack.extend(children.into_iter().rev());
    }
    None
}

fn normalize_php_snippet(snippet: &str) -> String {
    snippet
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>()
        .join("\n")
}

fn php_range(start_byte: usize, start: Point, end_byte: usize, end: Point) -> Range {
    Range {
        start_byte,
        end_byte,
        start_line: start.row + 1,
        end_line: end.row + 1,
    }
}
