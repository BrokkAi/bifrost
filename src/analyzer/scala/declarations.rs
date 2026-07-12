use crate::analyzer::{
    CallableArity, CodeUnit, CodeUnitType, ParameterMetadata, ProjectFile, SignatureMetadata,
};
use tree_sitter::{Node, Tree};

use super::imports::parse_scala_import_infos;
use super::supertypes::extract_scala_supertypes;

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

enum ScalaWork<'tree> {
    CompilationUnit {
        children: Vec<Node<'tree>>,
        index: usize,
        package_name: String,
        recovery_parent: Option<CodeUnit>,
    },
    TemplateBody {
        node: Node<'tree>,
        package_name: String,
        parent: CodeUnit,
    },
}

impl<'a> ScalaVisitor<'a> {
    fn visit_compilation_unit(&mut self, node: Node<'_>, package_name: &str) {
        let mut cursor = node.walk();
        let mut stack = vec![ScalaWork::CompilationUnit {
            children: node.named_children(&mut cursor).collect(),
            index: 0,
            package_name: package_name.to_string(),
            recovery_parent: None,
        }];
        while let Some(work) = stack.pop() {
            match work {
                ScalaWork::CompilationUnit {
                    children,
                    index,
                    package_name,
                    recovery_parent,
                } => self.process_compilation_unit(
                    children,
                    index,
                    package_name,
                    recovery_parent,
                    &mut stack,
                ),
                ScalaWork::TemplateBody {
                    node,
                    package_name,
                    parent,
                } => self.process_template_body(node, &package_name, &parent, &mut stack),
            }
        }
    }

    fn process_compilation_unit<'tree>(
        &mut self,
        children: Vec<Node<'tree>>,
        mut index: usize,
        mut current_package: String,
        mut recovery_parent: Option<CodeUnit>,
        stack: &mut Vec<ScalaWork<'tree>>,
    ) {
        while index < children.len() {
            let child = children[index];
            index += 1;
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
                            self.parsed.content_qualifier = current_package.clone();
                        }
                    }
                    if let Some(body) = child.child_by_field_name("body") {
                        stack.push(ScalaWork::CompilationUnit {
                            children,
                            index,
                            package_name: current_package.clone(),
                            recovery_parent: recovery_parent.clone(),
                        });
                        let mut cursor = body.walk();
                        stack.push(ScalaWork::CompilationUnit {
                            children: body.named_children(&mut cursor).collect(),
                            index: 0,
                            package_name: current_package.clone(),
                            recovery_parent: None,
                        });
                        return;
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
                | "enum_definition" => {
                    self.visit_type_declaration(child, &current_package, None, stack);
                }
                "function_definition" | "function_declaration" => {
                    self.visit_function(child, &current_package, recovery_parent.clone())
                }
                "val_definition" | "var_definition" | "val_declaration" | "var_declaration" => {
                    self.visit_field_declaration(child, &current_package, recovery_parent.clone())
                }
                "ERROR" => {
                    // tree-sitter-scala sometimes recovers annotated constructor headers as a
                    // top-level ERROR containing the class, followed by body members as siblings.
                    if recovery_parent.is_some() && scala_error_is_closing_brace(child, self.source)
                    {
                        recovery_parent = None;
                    } else if recovery_parent.is_none()
                        && let Some(type_node) = scala_error_type_declaration(child)
                        && let Some(parent) =
                            self.visit_type_declaration(type_node, &current_package, None, stack)
                    {
                        recovery_parent = Some(parent);
                    }
                }
                _ => {}
            }
        }
    }

    fn visit_type_declaration<'tree>(
        &mut self,
        node: Node<'tree>,
        package_name: &str,
        parent: Option<CodeUnit>,
        stack: &mut Vec<ScalaWork<'tree>>,
    ) -> Option<CodeUnit> {
        let name_node = scala_type_declaration_name_node(node)?;
        let raw_name = scala_node_text(name_node, self.source).trim();
        if raw_name.is_empty() {
            return None;
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
            return Some(code_unit);
        }

        self.parsed
            .add_code_unit(code_unit.clone(), node, self.source, parent.clone(), None);
        self.parsed
            .add_signature(code_unit.clone(), scala_type_signature(node, self.source));
        let raw_supertypes = extract_scala_supertypes(node, self.source);
        if !raw_supertypes.is_empty() {
            self.parsed
                .set_raw_supertypes(code_unit.clone(), raw_supertypes);
        }
        if node.kind() == "trait_definition" {
            self.parsed.set_scala_trait(code_unit.clone());
        }

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
            let signature = scala_primary_constructor_signature(node, self.source);
            self.parsed.add_signature_with_metadata(
                constructor,
                scala_class_signature_metadata(signature, node, self.source),
            );
            self.visit_class_parameter_fields(node, package_name, &code_unit);
        }

        if let Some(body) = node.child_by_field_name("body") {
            stack.push(ScalaWork::TemplateBody {
                node: body,
                package_name: package_name.to_string(),
                parent: code_unit.clone(),
            });
        }
        Some(code_unit)
    }

    fn visit_class_parameter_fields(
        &mut self,
        node: Node<'_>,
        package_name: &str,
        parent: &CodeUnit,
    ) {
        let Some(parameters) = node.child_by_field_name("class_parameters") else {
            return;
        };
        let is_case_class = scala_is_case_class_definition(node, self.source);
        let mut cursor = parameters.walk();
        for parameter in parameters.named_children(&mut cursor) {
            if parameter.kind() != "class_parameter" {
                continue;
            }
            let parameter_text = scala_node_text(parameter, self.source).trim_start();
            if !is_case_class
                && !parameter_text.starts_with("val ")
                && !parameter_text.starts_with("var ")
            {
                continue;
            }
            let Some(name_node) = parameter.child_by_field_name("name") else {
                continue;
            };
            let name = scala_node_text(name_node, self.source).trim();
            if name.is_empty() {
                continue;
            }
            let code_unit = CodeUnit::new(
                self.file.clone(),
                CodeUnitType::Field,
                package_name.to_string(),
                format!("{}.{}", parent.short_name(), name),
            );
            self.parsed.add_code_unit(
                code_unit.clone(),
                parameter,
                self.source,
                Some(parent.clone()),
                None,
            );
            self.parsed.add_signature(
                code_unit,
                scala_class_parameter_field_signature(parameter, self.source, name),
            );
        }
    }

    fn process_template_body<'tree>(
        &mut self,
        body: Node<'tree>,
        package_name: &str,
        parent: &CodeUnit,
        stack: &mut Vec<ScalaWork<'tree>>,
    ) {
        let mut cursor = body.walk();
        let children = body.named_children(&mut cursor).collect::<Vec<_>>();
        for child in children {
            match child.kind() {
                "import_declaration" => {
                    let raw = scala_node_text(child, self.source).trim().to_string();
                    if !raw.is_empty() {
                        self.parsed.imports.extend(parse_scala_import_infos(&raw));
                        self.parsed.import_statements.push(raw);
                    }
                }
                "function_definition" | "function_declaration" => {
                    self.visit_function(child, package_name, Some(parent.clone()))
                }
                "val_definition" | "var_definition" | "val_declaration" | "var_declaration" => {
                    self.visit_field_declaration(child, package_name, Some(parent.clone()))
                }
                "class_definition" | "object_definition" | "trait_definition"
                | "enum_definition" => {
                    self.visit_type_declaration(child, package_name, Some(parent.clone()), stack);
                }
                "extension_definition" => {
                    self.visit_extension_definition(child, package_name, parent, stack)
                }
                "simple_enum_case" => self.visit_enum_case(child, package_name, parent),
                "enum_case_definitions" | "enum_body" => {
                    stack.push(ScalaWork::TemplateBody {
                        node: child,
                        package_name: package_name.to_string(),
                        parent: parent.clone(),
                    });
                }
                _ => {}
            }
        }
    }

    fn visit_extension_definition<'tree>(
        &mut self,
        node: Node<'tree>,
        package_name: &str,
        parent: &CodeUnit,
        stack: &mut Vec<ScalaWork<'tree>>,
    ) {
        let receiver_parameters = node.child_by_field_name("parameters");
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            match child.kind() {
                "function_definition" | "function_declaration" => self.visit_extension_function(
                    child,
                    receiver_parameters,
                    package_name,
                    Some(parent.clone()),
                ),
                "val_definition" | "var_definition" | "val_declaration" | "var_declaration" => {
                    self.visit_field_declaration(child, package_name, Some(parent.clone()))
                }
                "class_definition" | "object_definition" | "trait_definition"
                | "enum_definition" => {
                    self.visit_type_declaration(child, package_name, Some(parent.clone()), stack);
                }
                "template_body" | "block" | "indented_block" => self.visit_extension_block(
                    child,
                    receiver_parameters,
                    package_name,
                    parent,
                    stack,
                ),
                _ => {}
            }
        }
    }

    fn visit_extension_block<'tree>(
        &mut self,
        node: Node<'tree>,
        receiver_parameters: Option<Node<'tree>>,
        package_name: &str,
        parent: &CodeUnit,
        stack: &mut Vec<ScalaWork<'tree>>,
    ) {
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            match child.kind() {
                "function_definition" | "function_declaration" => self.visit_extension_function(
                    child,
                    receiver_parameters,
                    package_name,
                    Some(parent.clone()),
                ),
                "val_definition" | "var_definition" | "val_declaration" | "var_declaration" => {
                    self.visit_field_declaration(child, package_name, Some(parent.clone()))
                }
                "class_definition" | "object_definition" | "trait_definition"
                | "enum_definition" => {
                    self.visit_type_declaration(child, package_name, Some(parent.clone()), stack);
                }
                "template_body" | "block" | "indented_block" => self.visit_extension_block(
                    child,
                    receiver_parameters,
                    package_name,
                    parent,
                    stack,
                ),
                _ => {}
            }
        }
    }

    fn visit_function(&mut self, node: Node<'_>, package_name: &str, parent: Option<CodeUnit>) {
        self.visit_function_with_signature(node, package_name, parent, None);
    }

    fn visit_extension_function(
        &mut self,
        node: Node<'_>,
        receiver_parameters: Option<Node<'_>>,
        package_name: &str,
        parent: Option<CodeUnit>,
    ) {
        self.visit_function_with_signature(
            node,
            package_name,
            parent,
            Some(scala_extension_function_signature(
                node,
                receiver_parameters,
                self.source,
            )),
        );
    }

    fn visit_function_with_signature(
        &mut self,
        node: Node<'_>,
        package_name: &str,
        parent: Option<CodeUnit>,
        signature: Option<String>,
    ) {
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
        let signature = signature.unwrap_or_else(|| scala_function_signature(node, self.source));
        self.parsed.add_signature_with_metadata(
            code_unit,
            scala_function_signature_metadata(signature, node, self.source),
        );
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

fn scala_type_declaration_name_node(node: Node<'_>) -> Option<Node<'_>> {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        match child.kind() {
            "identifier" => return Some(child),
            "ERROR" => {
                if let Some(identifier) = first_descendant_identifier(child) {
                    return Some(identifier);
                }
            }
            _ => {}
        }
    }
    None
}

fn scala_error_type_declaration(node: Node<'_>) -> Option<Node<'_>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor).find(|child| {
        matches!(
            child.kind(),
            "class_definition" | "object_definition" | "trait_definition" | "enum_definition"
        )
    })
}

fn scala_error_is_closing_brace(node: Node<'_>, source: &str) -> bool {
    scala_node_text(node, source).trim() == "}"
}

fn first_descendant_identifier(node: Node<'_>) -> Option<Node<'_>> {
    let mut cursor = node.walk();
    let mut stack = node.named_children(&mut cursor).collect::<Vec<_>>();
    stack.reverse();
    while let Some(child) = stack.pop() {
        if child.kind() == "identifier" {
            return Some(child);
        }
        let mut child_cursor = child.walk();
        let mut children = child.named_children(&mut child_cursor).collect::<Vec<_>>();
        children.reverse();
        stack.extend(children);
    }
    None
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
        .filter(|name| name.parent() == Some(node))
        .or_else(|| scala_type_declaration_name_node(node))
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
        .filter(|name| name.parent() == Some(node))
        .or_else(|| scala_type_declaration_name_node(node))
        .map(|name| scala_node_text(name, source).trim())
        .unwrap_or("");
    let params = node
        .child_by_field_name("class_parameters")
        .map(|child| scala_node_text(child, source).trim().to_string())
        .unwrap_or_default();
    format!("def {name}{params} = {{...}}")
}

fn scala_class_signature_metadata(
    signature: String,
    node: Node<'_>,
    source: &str,
) -> SignatureMetadata {
    let Some(parameters_node) = node.child_by_field_name("class_parameters") else {
        return SignatureMetadata::new(signature, Vec::new());
    };
    scala_signature_metadata_for_parameter_nodes(signature, &[parameters_node], source)
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

fn scala_extension_function_signature(
    node: Node<'_>,
    receiver_parameters: Option<Node<'_>>,
    source: &str,
) -> String {
    let receiver = receiver_parameters
        .map(|parameters| scala_node_text(parameters, source).trim().to_string())
        .unwrap_or_default();
    format!(
        "extension {receiver} {}",
        scala_function_signature(node, source)
    )
}

fn scala_function_signature_metadata(
    signature: String,
    node: Node<'_>,
    source: &str,
) -> SignatureMetadata {
    let mut parameter_nodes = Vec::new();
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.kind() == "parameters" {
            parameter_nodes.push(child);
        }
    }
    scala_signature_metadata_for_parameter_nodes(signature, &parameter_nodes, source)
}

fn scala_signature_metadata_for_parameter_nodes(
    signature: String,
    parameter_nodes: &[Node<'_>],
    source: &str,
) -> SignatureMetadata {
    let parameter_text = parameter_nodes
        .iter()
        .map(|node| scala_node_text(*node, source).trim().to_string())
        .collect::<Vec<_>>()
        .join("");
    if parameter_text.is_empty() {
        return SignatureMetadata::new(signature, Vec::new());
    }
    let Some(parameters_start) = signature.find(&parameter_text) else {
        return SignatureMetadata::new(signature, Vec::new());
    };
    let parameters_end = parameters_start + parameter_text.len();
    let mut search_start = parameters_start;
    let parameters = scala_parameter_label_nodes(parameter_nodes)
        .into_iter()
        .filter_map(|label_node| {
            let label = scala_node_text(label_node, source).trim();
            if label.is_empty() || search_start > parameters_end {
                return None;
            }
            let haystack = signature.get(search_start..parameters_end)?;
            let relative_start = haystack.find(label)?;
            let start_byte = search_start + relative_start;
            let end_byte = start_byte + label.len();
            search_start = end_byte;
            Some(ParameterMetadata::new(label, start_byte, end_byte))
        })
        .collect();
    let mut metadata = SignatureMetadata::new(signature, parameters);
    if let Some(arity) = scala_callable_arity(parameter_nodes.first().copied()) {
        metadata = metadata.with_callable_arity(arity);
    }
    metadata
}

fn scala_callable_arity(parameters: Option<Node<'_>>) -> Option<CallableArity> {
    let Some(parameters) = parameters else {
        return Some(CallableArity::exact(0));
    };
    let mut total = 0usize;
    let mut required = 0usize;
    let mut repeated = false;
    let mut cursor = parameters.walk();
    for parameter in parameters.named_children(&mut cursor) {
        if !matches!(parameter.kind(), "parameter" | "class_parameter") {
            continue;
        }
        total += 1;
        let is_repeated = parameter
            .child_by_field_name("type")
            .is_some_and(contains_repeated_parameter_type);
        repeated |= is_repeated;
        if parameter.child_by_field_name("default_value").is_none() && !is_repeated {
            required += 1;
        }
    }
    Some(CallableArity::new(required, total, repeated))
}

fn contains_repeated_parameter_type(node: Node<'_>) -> bool {
    let mut stack = vec![node];
    while let Some(current) = stack.pop() {
        if current.kind() == "repeated_parameter_type" {
            return true;
        }
        let mut cursor = current.walk();
        stack.extend(current.named_children(&mut cursor));
    }
    false
}

fn scala_parameter_label_nodes<'tree>(parameter_nodes: &[Node<'tree>]) -> Vec<Node<'tree>> {
    let mut labels = Vec::new();
    for node in parameter_nodes {
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            if matches!(child.kind(), "parameter" | "class_parameter")
                && let Some(name_node) = child.child_by_field_name("name")
            {
                labels.push(name_node);
            }
        }
    }
    labels
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

fn scala_class_parameter_field_signature(node: Node<'_>, source: &str, name: &str) -> String {
    let keyword = if scala_node_text(node, source)
        .trim_start()
        .starts_with("var ")
    {
        "var"
    } else {
        "val"
    };
    let type_text = node
        .child_by_field_name("type")
        .map(|child| format!(": {}", scala_node_text(child, source).trim()))
        .unwrap_or_default();
    let default_value = node
        .child_by_field_name("default_value")
        .map(|child| format!(" = {}", scala_node_text(child, source).trim()))
        .unwrap_or_default();
    format!("{keyword} {name}{type_text}{default_value}")
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

fn scala_is_case_class_definition(node: Node<'_>, source: &str) -> bool {
    let text = scala_node_text(node, source);
    let header = text.split(['(', '{']).next().unwrap_or(text);
    header.split_whitespace().any(|token| token == "case")
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
