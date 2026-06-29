use crate::analyzer::tree_sitter_analyzer::{WalkControl, walk_named_tree_preorder};
use crate::analyzer::{CodeUnit, CodeUnitType, ParameterMetadata, ProjectFile, SignatureMetadata};
use crate::hash::HashSet;
use tree_sitter::{Node, Tree};

use super::imports::{csharp_import_info, csharp_using_namespace, normalize_csharp_type_name};

pub(super) fn parse_csharp_file(
    file: &ProjectFile,
    source: &str,
    tree: &Tree,
) -> crate::analyzer::tree_sitter_analyzer::ParsedFile {
    let mut parsed = crate::analyzer::tree_sitter_analyzer::ParsedFile::new(String::new());
    collect_csharp_type_identifiers(tree.root_node(), source, &mut parsed.type_identifiers);
    let mut visitor = CSharpVisitor {
        file,
        source,
        parsed: &mut parsed,
    };
    visitor.visit_container(tree.root_node(), "", None);
    parsed
}

#[derive(Clone)]
struct CSharpScope {
    package_name: String,
    class_unit: Option<CodeUnit>,
}

struct CSharpWork<'tree> {
    node: Node<'tree>,
    scope: CSharpScope,
}

struct CSharpVisitor<'a> {
    file: &'a ProjectFile,
    source: &'a str,
    parsed: &'a mut crate::analyzer::tree_sitter_analyzer::ParsedFile,
}

impl<'a> CSharpVisitor<'a> {
    fn visit_container(
        &mut self,
        node: Node<'_>,
        package_name: &str,
        class_unit: Option<CodeUnit>,
    ) {
        let mut stack = Vec::new();
        self.push_children(
            node,
            CSharpScope {
                package_name: package_name.to_string(),
                class_unit,
            },
            &mut stack,
        );
        while let Some(work) = stack.pop() {
            self.visit_node(work.node, &work.scope, &mut stack);
        }
    }

    fn push_children<'tree>(
        &self,
        node: Node<'tree>,
        scope: CSharpScope,
        stack: &mut Vec<CSharpWork<'tree>>,
    ) {
        let mut cursor = node.walk();
        let children = node.named_children(&mut cursor).collect::<Vec<_>>();
        // A file-scoped namespace (`namespace X;`) has no body: its type declarations
        // are following SIBLINGS, not children. Apply its namespace to everything after
        // it so their package_name is populated. Block namespaces keep a body and flow
        // through `queue_namespace`.
        let mut current = scope;
        let mut scoped: Vec<(Node<'tree>, CSharpScope)> = Vec::with_capacity(children.len());
        for child in children {
            if child.kind() == "file_scoped_namespace_declaration" {
                if let Some(package_name) = self.namespace_scope_name(child, &current) {
                    current = CSharpScope {
                        package_name,
                        class_unit: current.class_unit.clone(),
                    };
                }
                continue;
            }
            scoped.push((child, current.clone()));
        }
        for (child, child_scope) in scoped.into_iter().rev() {
            stack.push(CSharpWork {
                node: child,
                scope: child_scope,
            });
        }
    }

    fn namespace_scope_name(&self, node: Node<'_>, scope: &CSharpScope) -> Option<String> {
        let name_node = node.child_by_field_name("name")?;
        let raw_name = cs_node_text(name_node, self.source).trim();
        if raw_name.is_empty() {
            return None;
        }
        Some(if scope.package_name.is_empty() {
            raw_name.to_string()
        } else {
            format!("{}.{}", scope.package_name, raw_name)
        })
    }

    fn visit_node<'tree>(
        &mut self,
        node: Node<'tree>,
        scope: &CSharpScope,
        stack: &mut Vec<CSharpWork<'tree>>,
    ) {
        match node.kind() {
            // Block namespaces only; file-scoped namespaces are handled in push_children
            // (their types are following siblings, not body children).
            "namespace_declaration" => self.queue_namespace(node, scope, stack),
            "class_declaration"
            | "interface_declaration"
            | "struct_declaration"
            | "enum_declaration"
            | "record_declaration"
            | "record_struct_declaration" => self.visit_type_declaration(node, scope, stack),
            "method_declaration" => self.visit_method(node, scope),
            "constructor_declaration" => self.visit_constructor(node, scope),
            "property_declaration" => self.visit_property(node, scope),
            "field_declaration" => self.visit_field_declaration(node, scope),
            "enum_member_declaration" => self.visit_enum_member(node, scope),
            "using_directive" => self.visit_using_directive(node),
            _ => {}
        }
    }

    fn visit_using_directive(&mut self, node: Node<'_>) {
        let raw = cs_node_text(node, self.source).trim().to_string();
        if raw.is_empty() {
            return;
        }
        self.parsed.import_statements.push(raw.clone());
        if csharp_using_namespace(&raw).is_some() {
            self.parsed.imports.push(csharp_import_info(raw));
        }
    }

    fn queue_namespace<'tree>(
        &mut self,
        node: Node<'tree>,
        scope: &CSharpScope,
        stack: &mut Vec<CSharpWork<'tree>>,
    ) {
        let Some(name_node) = node.child_by_field_name("name") else {
            return;
        };
        let raw_name = cs_node_text(name_node, self.source).trim();
        if raw_name.is_empty() {
            return;
        }
        let package_name = if scope.package_name.is_empty() {
            raw_name.to_string()
        } else {
            format!("{}.{}", scope.package_name, raw_name)
        };
        if let Some(body) = cs_namespace_body(node) {
            self.push_children(
                body,
                CSharpScope {
                    package_name,
                    class_unit: scope.class_unit.clone(),
                },
                stack,
            );
        }
    }

    fn visit_type_declaration<'tree>(
        &mut self,
        node: Node<'tree>,
        scope: &CSharpScope,
        stack: &mut Vec<CSharpWork<'tree>>,
    ) {
        let Some(name_node) = node.child_by_field_name("name") else {
            return;
        };
        let name = cs_node_text(name_node, self.source).trim();
        if name.is_empty() {
            return;
        }

        let short_name = if let Some(parent) = &scope.class_unit {
            format!("{}${name}", parent.short_name())
        } else {
            name.to_string()
        };
        let code_unit = CodeUnit::new(
            self.file.clone(),
            CodeUnitType::Class,
            scope.package_name.clone(),
            short_name,
        );
        if self.parsed.declarations.contains(&code_unit) {
            return;
        }
        self.parsed.add_code_unit(
            code_unit.clone(),
            node,
            self.source,
            scope.class_unit.clone(),
            None,
        );
        self.parsed.set_raw_supertypes(
            code_unit.clone(),
            extract_csharp_supertypes(node, self.source),
        );
        self.parsed
            .add_signature(code_unit.clone(), csharp_type_signature(node, self.source));

        if let Some(body) = cs_type_body(node) {
            self.push_children(
                body,
                CSharpScope {
                    package_name: scope.package_name.clone(),
                    class_unit: Some(code_unit),
                },
                stack,
            );
        }
    }

    fn visit_method(&mut self, node: Node<'_>, scope: &CSharpScope) {
        let Some(parent) = &scope.class_unit else {
            return;
        };
        let Some(name_node) = node.child_by_field_name("name") else {
            return;
        };
        let name = cs_node_text(name_node, self.source).trim();
        if name.is_empty() {
            return;
        }
        let signature_key = csharp_parameter_key(node, self.source);
        let code_unit = CodeUnit::with_signature(
            self.file.clone(),
            CodeUnitType::Function,
            scope.package_name.clone(),
            format!("{}.{}", parent.short_name(), name),
            Some(signature_key),
            false,
        );
        self.parsed.add_code_unit(
            code_unit.clone(),
            node,
            self.source,
            Some(parent.clone()),
            None,
        );
        let signature = csharp_method_skeleton(node, self.source);
        self.parsed.add_signature_with_metadata(
            code_unit,
            csharp_signature_metadata(signature, node, self.source),
        );
    }

    fn visit_constructor(&mut self, node: Node<'_>, scope: &CSharpScope) {
        let Some(parent) = &scope.class_unit else {
            return;
        };
        let Some(name_node) = node.child_by_field_name("name") else {
            return;
        };
        let name = cs_node_text(name_node, self.source).trim();
        if name.is_empty() {
            return;
        }
        let code_unit = CodeUnit::with_signature(
            self.file.clone(),
            CodeUnitType::Function,
            scope.package_name.clone(),
            format!("{}.{}", parent.short_name(), name),
            Some(csharp_parameter_key(node, self.source)),
            false,
        );
        self.parsed.add_code_unit(
            code_unit.clone(),
            node,
            self.source,
            Some(parent.clone()),
            None,
        );
        let signature = csharp_constructor_skeleton(node, self.source);
        self.parsed.add_signature_with_metadata(
            code_unit,
            csharp_signature_metadata(signature, node, self.source),
        );
    }

    fn visit_property(&mut self, node: Node<'_>, scope: &CSharpScope) {
        let Some(parent) = &scope.class_unit else {
            return;
        };
        let Some(name_node) = node.child_by_field_name("name") else {
            return;
        };
        let name = cs_node_text(name_node, self.source).trim();
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
            .add_signature(code_unit, csharp_property_signature(node, self.source));
    }

    fn visit_field_declaration(&mut self, node: Node<'_>, scope: &CSharpScope) {
        let Some(parent) = &scope.class_unit else {
            return;
        };
        let Some(declaration) = node
            .child_by_field_name("declaration")
            .or_else(|| first_named_child_of_kind(node, "variable_declaration"))
        else {
            return;
        };

        let prefix = csharp_field_prefix(node, declaration, self.source);
        let type_text = declaration
            .child_by_field_name("type")
            .map(|child| normalize_cs_whitespace(cs_node_text(child, self.source)))
            .unwrap_or_default();
        let declaration_text = normalize_cs_whitespace(cs_node_text(node, self.source));

        let mut cursor = declaration.walk();
        for child in declaration.named_children(&mut cursor) {
            if child.kind() != "variable_declarator" {
                continue;
            }
            let Some(name_node) = child.child_by_field_name("name") else {
                continue;
            };
            let name = cs_node_text(name_node, self.source).trim();
            if name.is_empty() {
                continue;
            }
            let code_unit = CodeUnit::new(
                self.file.clone(),
                CodeUnitType::Field,
                scope.package_name.clone(),
                format!("{}.{}", parent.short_name(), name),
            );
            self.parsed.add_code_unit(
                code_unit.clone(),
                child,
                self.source,
                Some(parent.clone()),
                None,
            );
            self.parsed.add_signature(
                code_unit,
                csharp_field_signature(&prefix, &type_text, &declaration_text, child, self.source),
            );
        }
    }

    fn visit_enum_member(&mut self, node: Node<'_>, scope: &CSharpScope) {
        let Some(parent) = &scope.class_unit else {
            return;
        };
        let Some(name_node) = node.child_by_field_name("name") else {
            return;
        };
        let name = cs_node_text(name_node, self.source).trim();
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
        self.parsed.add_signature(
            code_unit,
            normalize_cs_whitespace(cs_node_text(node, self.source)),
        );
    }
}

fn collect_csharp_type_identifiers(
    node: Node<'_>,
    source: &str,
    identifiers: &mut HashSet<String>,
) {
    walk_named_tree_preorder(node, true, |node| {
        if is_csharp_type_position_node(node)
            && matches!(
                node.kind(),
                "identifier"
                    | "qualified_name"
                    | "generic_name"
                    | "nullable_type"
                    | "array_type"
                    | "type"
            )
        {
            let text = normalize_csharp_type_name(cs_node_text(node, source));
            if !text.is_empty() {
                identifiers.insert(text);
            }
        }
        WalkControl::Continue
    });
}

fn is_csharp_type_position_node(mut node: Node<'_>) -> bool {
    while let Some(parent) = node.parent() {
        if parent
            .child_by_field_name("type")
            .is_some_and(|type_node| same_cs_node(type_node, node))
            || parent
                .child_by_field_name("return_type")
                .is_some_and(|type_node| same_cs_node(type_node, node))
        {
            return true;
        }
        if parent.kind() == "type" {
            return true;
        }
        if parent.kind() == "object_creation_expression" {
            return true;
        }
        if matches!(
            parent.kind(),
            "class_declaration"
                | "interface_declaration"
                | "struct_declaration"
                | "enum_declaration"
                | "record_declaration"
                | "record_struct_declaration"
        ) && !parent
            .child_by_field_name("name")
            .is_some_and(|name| same_cs_node(name, node))
        {
            return true;
        }
        if matches!(
            parent.kind(),
            "qualified_name"
                | "generic_name"
                | "nullable_type"
                | "array_type"
                | "type_argument_list"
                | "base_list"
        ) {
            node = parent;
            continue;
        }
        return false;
    }
    false
}

fn same_cs_node(left: Node<'_>, right: Node<'_>) -> bool {
    left.start_byte() == right.start_byte() && left.end_byte() == right.end_byte()
}

fn cs_node_text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    source.get(node.start_byte()..node.end_byte()).unwrap_or("")
}

fn normalize_cs_whitespace(value: &str) -> String {
    let mut result = String::new();
    let mut prev_space = false;
    for ch in value.chars() {
        if ch.is_whitespace() {
            if !prev_space {
                result.push(' ');
            }
            prev_space = true;
        } else {
            result.push(ch);
            prev_space = false;
        }
    }
    result.trim().to_string()
}

fn cs_namespace_body(node: Node<'_>) -> Option<Node<'_>> {
    node.child_by_field_name("body")
        .or_else(|| last_named_child(node))
}

fn cs_type_body(node: Node<'_>) -> Option<Node<'_>> {
    node.child_by_field_name("body")
        .or_else(|| first_named_child_of_kind(node, "declaration_list"))
}

fn csharp_type_signature(node: Node<'_>, source: &str) -> String {
    let text = normalize_cs_whitespace(cs_node_text(node, source));
    let head = text.split('{').next().unwrap_or(text.as_str()).trim();
    format!("{head} {{")
}

fn extract_csharp_supertypes(node: Node<'_>, source: &str) -> Vec<String> {
    let Some(base_list) = first_named_child_of_kind(node, "base_list") else {
        return Vec::new();
    };
    let mut supertypes = Vec::new();
    let mut cursor = base_list.walk();
    for child in base_list.named_children(&mut cursor) {
        match child.kind() {
            "identifier"
            | "qualified_name"
            | "generic_name"
            | "alias_qualified_name"
            | "nullable_type"
            | "array_type"
            | "predefined_type" => {
                let text = normalize_cs_whitespace(cs_node_text(child, source));
                if !text.is_empty() {
                    supertypes.push(text);
                }
            }
            _ => {}
        }
    }
    supertypes
}

fn csharp_method_skeleton(node: Node<'_>, source: &str) -> String {
    let text = normalize_cs_whitespace(cs_node_text(node, source));
    let head = text.split('{').next().unwrap_or(text.as_str()).trim();
    format!("{} {{ … }}", head.trim_end_matches(';').trim())
}

fn csharp_constructor_skeleton(node: Node<'_>, source: &str) -> String {
    csharp_method_skeleton(node, source)
}

fn csharp_signature_metadata(signature: String, node: Node<'_>, source: &str) -> SignatureMetadata {
    let parameter_text = csharp_rendered_parameter_text(node, source);
    let Some(parameters_start) = signature.find(&parameter_text) else {
        return SignatureMetadata::new(signature, Vec::new());
    };
    let parameters_end = parameters_start + parameter_text.len();
    let mut search_start = parameters_start;
    let parameters = csharp_parameter_label_nodes(node)
        .into_iter()
        .filter_map(|label_node| {
            let label = normalize_cs_whitespace(cs_node_text(label_node, source));
            if label.is_empty() || search_start > parameters_end {
                return None;
            }
            let haystack = signature.get(search_start..parameters_end)?;
            let relative_start = haystack.find(&label)?;
            let start_byte = search_start + relative_start;
            let end_byte = start_byte + label.len();
            search_start = end_byte;
            Some(ParameterMetadata::new(label, start_byte, end_byte))
        })
        .collect();
    SignatureMetadata::new(signature, parameters)
}

fn csharp_rendered_parameter_text(node: Node<'_>, source: &str) -> String {
    node.child_by_field_name("parameters")
        .map(|parameters| normalize_cs_whitespace(cs_node_text(parameters, source)))
        .unwrap_or_else(|| "()".to_string())
}

fn csharp_parameter_label_nodes(node: Node<'_>) -> Vec<Node<'_>> {
    let Some(parameters) = node.child_by_field_name("parameters") else {
        return Vec::new();
    };
    let mut labels = Vec::new();
    let mut cursor = parameters.walk();
    for child in parameters.named_children(&mut cursor) {
        if child.kind() != "parameter" {
            continue;
        }
        if let Some(name) = child.child_by_field_name("name") {
            labels.push(name);
            continue;
        }
        let mut param_cursor = child.walk();
        if let Some(name) = child
            .named_children(&mut param_cursor)
            .find(|candidate| candidate.kind() == "identifier")
        {
            labels.push(name);
        }
    }
    labels
}

fn csharp_property_signature(node: Node<'_>, source: &str) -> String {
    normalize_cs_whitespace(cs_node_text(node, source))
}

fn csharp_parameter_key(node: Node<'_>, source: &str) -> String {
    let Some(parameters) = node.child_by_field_name("parameters") else {
        return "()".to_string();
    };
    let mut parts = Vec::new();
    let mut cursor = parameters.walk();
    for child in parameters.named_children(&mut cursor) {
        if child.kind() != "parameter" {
            continue;
        }
        let part = child
            .child_by_field_name("type")
            .map(|type_node| normalize_cs_whitespace(cs_node_text(type_node, source)))
            .unwrap_or_else(|| normalize_cs_whitespace(cs_node_text(child, source)));
        parts.push(part);
    }
    format!("({})", parts.join(", "))
}

fn csharp_field_prefix(field_node: Node<'_>, declaration: Node<'_>, source: &str) -> String {
    let field_text = cs_node_text(field_node, source);
    let end = declaration
        .start_byte()
        .saturating_sub(field_node.start_byte());
    let prefix = field_text.get(..end).unwrap_or(field_text);
    let prefix = normalize_cs_whitespace(prefix);
    regex::Regex::new(r"^(?:\[[^\]]+\]\s*)+")
        .ok()
        .map(|regex| regex.replace(&prefix, "").trim().to_string())
        .unwrap_or(prefix)
}

fn csharp_field_signature(
    prefix: &str,
    type_text: &str,
    declaration_text: &str,
    declarator: Node<'_>,
    source: &str,
) -> String {
    let name = declarator
        .child_by_field_name("name")
        .map(|child| cs_node_text(child, source).trim().to_string())
        .unwrap_or_default();
    let initializer = declarator
        .child_by_field_name("value")
        .or_else(|| declarator.child_by_field_name("initializer"))
        .and_then(|value| csharp_literal_initializer(value, source));
    let initializer =
        initializer.or_else(|| csharp_literal_initializer_from_text(declaration_text, &name));

    let base = if prefix.is_empty() {
        format!("{type_text} {name}")
    } else {
        format!("{prefix} {type_text} {name}")
    };
    let base = normalize_cs_whitespace(&base);
    if let Some(initializer) = initializer {
        format!("{base} = {initializer};")
    } else {
        format!("{base};")
    }
}

fn csharp_literal_initializer(node: Node<'_>, source: &str) -> Option<String> {
    let kind = node.kind();
    if matches!(
        kind,
        "integer_literal"
            | "real_literal"
            | "string_literal"
            | "character_literal"
            | "boolean_literal"
            | "null_literal"
    ) {
        return Some(normalize_cs_whitespace(cs_node_text(node, source)));
    }
    None
}

fn csharp_literal_initializer_from_text(declaration_text: &str, name: &str) -> Option<String> {
    let pattern = format!(
        r#"\b{}\s*=\s*("([^"\\]|\\.)*"|'([^'\\]|\\.)*'|[-+]?\d+(?:\.\d+)?|true|false|null)\s*(?:,|;)"#,
        regex::escape(name)
    );
    regex::Regex::new(&pattern)
        .ok()
        .and_then(|regex| regex.captures(declaration_text))
        .and_then(|captures| captures.get(1))
        .map(|value| value.as_str().to_string())
}

fn first_named_child_of_kind<'a>(node: Node<'a>, kind: &str) -> Option<Node<'a>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .find(|child| child.kind() == kind)
}

fn last_named_child(node: Node<'_>) -> Option<Node<'_>> {
    let count = node.named_child_count();
    if count == 0 {
        None
    } else {
        node.named_child(count - 1)
    }
}
