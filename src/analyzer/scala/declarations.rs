use crate::analyzer::{CodeUnit, CodeUnitType, ProjectFile};
use tree_sitter::{Node, Tree};

use super::imports::parse_scala_import_infos;

pub(super) fn parse_scala_file(
    file: &ProjectFile,
    source: &str,
    tree: &Tree,
) -> crate::analyzer::tree_sitter_analyzer::ParsedFile {
    let mut parsed = crate::analyzer::tree_sitter_analyzer::ParsedFile::new(String::new());
    let mut visitor = ScalaVisitor {
        file,
        source,
        parsed: &mut parsed,
    };
    visitor.visit_compilation_unit(tree.root_node(), "");
    parsed
}

struct ScalaVisitor<'a> {
    file: &'a ProjectFile,
    source: &'a str,
    parsed: &'a mut crate::analyzer::tree_sitter_analyzer::ParsedFile,
}

impl<'a> ScalaVisitor<'a> {
    fn visit_compilation_unit(&mut self, node: Node<'_>, package_name: &str) {
        let mut current_package = package_name.to_string();
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            match child.kind() {
                "package_clause" => {
                    let package = scala_package_name(child, self.source);
                    if !package.is_empty() {
                        current_package = if current_package.is_empty() {
                            package
                        } else {
                            format!("{current_package}.{package}")
                        };
                        if self.parsed.package_name.is_empty() {
                            self.parsed.package_name = current_package.clone();
                        }
                    }
                    if let Some(body) = child.child_by_field_name("body") {
                        self.visit_compilation_unit(body, &current_package);
                    }
                }
                "import_declaration" => {
                    let raw = scala_node_text(child, self.source).trim().to_string();
                    if !raw.is_empty() {
                        self.parsed.imports.extend(parse_scala_import_infos(&raw));
                        self.parsed.import_statements.push(raw);
                    }
                }
                "class_definition" | "object_definition" | "trait_definition"
                | "enum_definition" => self.visit_type_declaration(child, &current_package, None),
                "function_definition" => self.visit_function(child, &current_package, None),
                "val_definition" | "var_definition" => {
                    self.visit_field_declaration(child, &current_package, None)
                }
                _ => {}
            }
        }
    }

    fn visit_type_declaration(
        &mut self,
        node: Node<'_>,
        package_name: &str,
        parent: Option<CodeUnit>,
    ) {
        let Some(name_node) = node.child_by_field_name("name") else {
            return;
        };
        let raw_name = scala_node_text(name_node, self.source).trim();
        if raw_name.is_empty() {
            return;
        }

        let display_name = if node.kind() == "object_definition" {
            format!("{raw_name}$")
        } else {
            raw_name.to_string()
        };
        let short_name = if let Some(parent) = &parent {
            format!("{}.{}", parent.short_name(), display_name)
        } else {
            display_name
        };
        let code_unit = CodeUnit::new(
            self.file.clone(),
            CodeUnitType::Class,
            package_name.to_string(),
            short_name,
        );
        if self.parsed.declarations.contains(&code_unit) {
            return;
        }

        self.parsed
            .add_code_unit(code_unit.clone(), node, self.source, parent.clone(), None);
        self.parsed
            .add_signature(code_unit.clone(), scala_type_signature(node, self.source));

        if node.kind() == "class_definition"
            && node.child_by_field_name("class_parameters").is_some()
        {
            let constructor = CodeUnit::new(
                self.file.clone(),
                CodeUnitType::Function,
                package_name.to_string(),
                format!("{}.{}", code_unit.short_name(), raw_name),
            )
            .with_synthetic(true);
            self.parsed.add_code_unit(
                constructor.clone(),
                node,
                self.source,
                Some(code_unit.clone()),
                None,
            );
            self.parsed.add_signature(
                constructor,
                scala_primary_constructor_signature(node, self.source),
            );
        }

        if let Some(body) = node.child_by_field_name("body") {
            self.visit_template_body(body, package_name, &code_unit);
        }
    }

    fn visit_template_body(&mut self, body: Node<'_>, package_name: &str, parent: &CodeUnit) {
        let mut cursor = body.walk();
        for child in body.named_children(&mut cursor) {
            match child.kind() {
                "function_definition" => {
                    self.visit_function(child, package_name, Some(parent.clone()))
                }
                "val_definition" | "var_definition" => {
                    self.visit_field_declaration(child, package_name, Some(parent.clone()))
                }
                "class_definition" | "object_definition" | "trait_definition"
                | "enum_definition" => {
                    self.visit_type_declaration(child, package_name, Some(parent.clone()))
                }
                "simple_enum_case" => self.visit_enum_case(child, package_name, parent),
                "enum_case_definitions" | "enum_body" => {
                    self.visit_template_body(child, package_name, parent)
                }
                _ => {}
            }
        }
    }

    fn visit_function(&mut self, node: Node<'_>, package_name: &str, parent: Option<CodeUnit>) {
        let Some(name_node) = node.child_by_field_name("name") else {
            return;
        };
        let raw_name = scala_node_text(name_node, self.source).trim();
        if raw_name.is_empty() {
            return;
        }

        let effective_name = if raw_name == "this" {
            parent
                .as_ref()
                .map(|code_unit| last_segment(code_unit.short_name()).to_string())
                .unwrap_or_else(|| raw_name.to_string())
        } else {
            raw_name.to_string()
        };
        let short_name = if let Some(parent) = &parent {
            format!("{}.{}", parent.short_name(), effective_name)
        } else {
            effective_name
        };

        let code_unit = CodeUnit::new(
            self.file.clone(),
            CodeUnitType::Function,
            package_name.to_string(),
            short_name,
        );
        self.parsed
            .add_code_unit(code_unit.clone(), node, self.source, parent, None);
        self.parsed
            .add_signature(code_unit, scala_function_signature(node, self.source));
    }

    fn visit_field_declaration(
        &mut self,
        node: Node<'_>,
        package_name: &str,
        parent: Option<CodeUnit>,
    ) {
        let Some(pattern) = node.child_by_field_name("pattern") else {
            return;
        };

        for name in scala_pattern_names(pattern, self.source) {
            let short_name = if let Some(parent) = &parent {
                format!("{}.{}", parent.short_name(), name)
            } else {
                name.clone()
            };
            let code_unit = CodeUnit::new(
                self.file.clone(),
                CodeUnitType::Field,
                package_name.to_string(),
                short_name,
            );
            self.parsed
                .add_code_unit(code_unit.clone(), node, self.source, parent.clone(), None);
            self.parsed
                .add_signature(code_unit, scala_field_signature(node, self.source, &name));
        }
    }

    fn visit_enum_case(&mut self, node: Node<'_>, package_name: &str, parent: &CodeUnit) {
        let Some(name_node) = node.child_by_field_name("name") else {
            return;
        };
        let name = scala_node_text(name_node, self.source).trim();
        if name.is_empty() {
            return;
        }

        let code_unit = CodeUnit::new(
            self.file.clone(),
            CodeUnitType::Field,
            package_name.to_string(),
            format!("{}.{}", parent.short_name(), name),
        );
        self.parsed.add_code_unit(
            code_unit.clone(),
            node,
            self.source,
            Some(parent.clone()),
            None,
        );
        self.parsed.add_signature(code_unit, format!("case {name}"));
    }
}

fn scala_node_text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    &source[node.byte_range()]
}

fn scala_package_name(node: Node<'_>, source: &str) -> String {
    node.child_by_field_name("name")
        .map(|name| scala_node_text(name, source).trim().to_string())
        .unwrap_or_default()
}

fn scala_type_signature(node: Node<'_>, source: &str) -> String {
    let keyword = match node.kind() {
        "class_definition" => "class",
        "object_definition" => "object",
        "trait_definition" => "trait",
        "enum_definition" => "enum",
        _ => "class",
    };
    let name = node
        .child_by_field_name("name")
        .map(|name| scala_node_text(name, source).trim())
        .unwrap_or("");
    let type_params = node
        .child_by_field_name("type_parameters")
        .map(|child| scala_node_text(child, source).trim().to_string())
        .unwrap_or_default();
    let class_params = node
        .child_by_field_name("class_parameters")
        .map(|child| scala_node_text(child, source).trim().to_string())
        .unwrap_or_default();
    format!(
        "{}{} {}{}{} {{",
        scala_modifier_prefix(node, source),
        keyword,
        name,
        type_params,
        class_params
    )
}

fn scala_primary_constructor_signature(node: Node<'_>, source: &str) -> String {
    let name = node
        .child_by_field_name("name")
        .map(|name| scala_node_text(name, source).trim())
        .unwrap_or("");
    let params = node
        .child_by_field_name("class_parameters")
        .map(|child| scala_node_text(child, source).trim().to_string())
        .unwrap_or_default();
    format!("def {name}{params} = {{...}}")
}

fn scala_function_signature(node: Node<'_>, source: &str) -> String {
    let name = node
        .child_by_field_name("name")
        .map(|name| scala_node_text(name, source).trim())
        .unwrap_or("");
    let mut parts = Vec::new();
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if matches!(child.kind(), "type_parameters" | "parameters") {
            parts.push(scala_node_text(child, source).trim().to_string());
        }
    }
    let return_type = node
        .child_by_field_name("return_type")
        .map(|child| format!(": {}", scala_node_text(child, source).trim()))
        .unwrap_or_default();

    format!(
        "{}def {}{}{} = {{...}}",
        scala_modifier_prefix(node, source),
        name,
        parts.join(""),
        return_type
    )
}

fn scala_field_signature(node: Node<'_>, source: &str, name: &str) -> String {
    let keyword = if node.kind() == "var_definition" {
        "var"
    } else {
        "val"
    };
    let type_text = node
        .child_by_field_name("type")
        .map(|child| format!(": {}", scala_node_text(child, source).trim()))
        .unwrap_or_default();
    let initializer = node
        .child_by_field_name("value")
        .and_then(|value| scala_literal_initializer(value, source, node.start_position().column))
        .map(|value| format!(" = {value}"))
        .unwrap_or_default();

    format!(
        "{}{} {}{}{}",
        scala_modifier_prefix(node, source),
        keyword,
        name,
        type_text,
        initializer
    )
}

fn scala_modifier_prefix(node: Node<'_>, source: &str) -> String {
    let mut modifiers = Vec::new();
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        match child.kind() {
            "modifiers" | "access_modifier" => {
                let text = scala_node_text(child, source).trim();
                if !text.is_empty() {
                    modifiers.push(text.to_string());
                }
            }
            _ => {}
        }
    }

    if modifiers.is_empty() {
        String::new()
    } else {
        format!("{} ", modifiers.join(" "))
    }
}

fn scala_pattern_names(node: Node<'_>, source: &str) -> Vec<String> {
    match node.kind() {
        "identifier" | "operator_identifier" => {
            vec![scala_node_text(node, source).trim().to_string()]
        }
        "identifiers" => {
            let mut names = Vec::new();
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                if matches!(child.kind(), "identifier" | "operator_identifier") {
                    let text = scala_node_text(child, source).trim();
                    if !text.is_empty() {
                        names.push(text.to_string());
                    }
                }
            }
            names
        }
        _ => {
            let text = scala_node_text(node, source).trim();
            if text.is_empty() {
                Vec::new()
            } else {
                vec![text.to_string()]
            }
        }
    }
}

fn scala_literal_initializer(
    node: Node<'_>,
    source: &str,
    declaration_indent: usize,
) -> Option<String> {
    let kind = node.kind();
    if kind == "string"
        || kind.ends_with("_literal")
        || matches!(kind, "true" | "false" | "null" | "null_literal")
    {
        let text = scala_node_text(node, source).trim().to_string();
        Some(strip_declaration_indent(&text, declaration_indent))
    } else {
        None
    }
}

pub(super) fn last_segment(name: &str) -> &str {
    name.rsplit('.').next().unwrap_or(name)
}

fn strip_declaration_indent(text: &str, declaration_indent: usize) -> String {
    let continuation_indent = declaration_indent.saturating_sub(2);
    let mut lines = text.lines();
    let Some(first) = lines.next() else {
        return String::new();
    };
    let mut normalized = vec![first.to_string()];
    for line in lines {
        let trimmed = if line.trim().is_empty() {
            String::new()
        } else {
            line.chars().skip(continuation_indent).collect::<String>()
        };
        normalized.push(trimmed);
    }
    normalized.join("\n")
}
