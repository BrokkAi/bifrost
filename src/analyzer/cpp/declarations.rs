use super::*;
use regex::Regex;
use tree_sitter::Node;

#[derive(Clone)]
struct ScopeInfo {
    package_name: String,
    module: Option<CodeUnit>,
    class_unit: Option<CodeUnit>,
    template_signature: Option<String>,
}

pub(super) struct CppVisitor<'a> {
    pub(super) file: &'a ProjectFile,
    pub(super) source: &'a str,
    pub(super) parsed: &'a mut crate::analyzer::tree_sitter_analyzer::ParsedFile,
}

impl<'a> CppVisitor<'a> {
    pub(super) fn visit_container(
        &mut self,
        node: Node<'_>,
        package_name: &str,
        module: Option<CodeUnit>,
        class_unit: Option<CodeUnit>,
        template_signature: Option<String>,
    ) {
        let scope = ScopeInfo {
            package_name: package_name.to_string(),
            module,
            class_unit,
            template_signature,
        };
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            self.visit_node(child, &scope);
        }
    }

    fn visit_node(&mut self, node: Node<'_>, scope: &ScopeInfo) {
        match node.kind() {
            "template_declaration" => {
                let mut cursor = node.walk();
                for child in node.named_children(&mut cursor) {
                    match child.kind() {
                        "class_specifier"
                        | "struct_specifier"
                        | "union_specifier"
                        | "enum_specifier"
                        | "function_definition"
                        | "declaration"
                        | "field_declaration"
                        | "namespace_definition" => {
                            let mut template_scope = scope.clone();
                            template_scope.template_signature =
                                cpp_template_signature(node, child, self.source);
                            self.visit_node(child, &template_scope)
                        }
                        _ => {}
                    }
                }
            }
            "namespace_definition" => self.visit_namespace(node, scope),
            "class_specifier" | "struct_specifier" | "union_specifier" | "enum_specifier" => {
                self.visit_class_like(node, scope)
            }
            "function_definition" => self.visit_function_definition(node, scope),
            "declaration" => self.visit_declaration(node, scope, false),
            "field_declaration" => self.visit_declaration(node, scope, true),
            "type_definition" | "alias_declaration" => {}
            "preproc_include" => self.visit_include(node),
            "preproc_if"
            | "preproc_ifdef"
            | "preproc_ifndef"
            | "preproc_else"
            | "preproc_elif"
            | "preproc_function_def" => self.visit_container(
                node,
                &scope.package_name,
                scope.module.clone(),
                scope.class_unit.clone(),
                scope.template_signature.clone(),
            ),
            _ => {}
        }
    }

    fn visit_namespace(&mut self, node: Node<'_>, scope: &ScopeInfo) {
        let name_node = node.child_by_field_name("name");
        let Some(name_node) = name_node else {
            if let Some(body) = cpp_body_node(node) {
                self.visit_container(
                    body,
                    &scope.package_name,
                    scope.module.clone(),
                    scope.class_unit.clone(),
                    scope.template_signature.clone(),
                );
            }
            return;
        };
        let name = normalize_cpp_whitespace(node_text(name_node, self.source));
        if name.is_empty() {
            return;
        }
        let full_name = if scope.package_name.is_empty() {
            name
        } else {
            format!("{}::{}", scope.package_name, name)
        };
        let module = CodeUnit::new(
            self.file.clone(),
            CodeUnitType::Module,
            "",
            full_name.clone(),
        );
        if !self.parsed.declarations.contains(&module) {
            self.parsed
                .add_code_unit(module.clone(), node, self.source, None, None);
        }

        if let Some(body) = cpp_body_node(node) {
            self.visit_container(
                body,
                &full_name,
                Some(module),
                scope.class_unit.clone(),
                scope.template_signature.clone(),
            );
        }
    }

    fn visit_class_like(&mut self, node: Node<'_>, scope: &ScopeInfo) {
        let Some(name_node) = node.child_by_field_name("name") else {
            return;
        };
        let name = normalize_cpp_whitespace(node_text(name_node, self.source));
        if name.is_empty() {
            return;
        }

        let short_name = if let Some(parent) = &scope.class_unit {
            format!("{}${name}", parent.short_name())
        } else {
            name
        };
        let code_unit = CodeUnit::with_signature(
            self.file.clone(),
            CodeUnitType::Class,
            scope.package_name.clone(),
            short_name,
            scope.template_signature.clone(),
            false,
        );
        let has_body = cpp_body_node(node).is_some();
        if !has_body && self.parsed.declarations.contains(&code_unit) {
            return;
        }
        if has_body {
            self.parsed
                .replace_code_unit(code_unit.clone(), node, self.source, None, None);
        } else {
            self.parsed
                .add_code_unit(code_unit.clone(), node, self.source, None, None);
        }
        self.parsed.add_signature(
            code_unit.clone(),
            render_cpp_type_signature(node, self.source, scope.template_signature.as_deref()),
        );
        if let Some(parent) = &scope.class_unit {
            self.parsed.add_child(parent.clone(), code_unit.clone());
        } else if let Some(module) = &scope.module {
            self.parsed.add_child(module.clone(), code_unit.clone());
        }

        if let Some(body) = cpp_body_node(node) {
            let mut nested_scope = scope.clone();
            nested_scope.class_unit = Some(code_unit.clone());
            nested_scope.template_signature = scope.template_signature.clone();
            self.visit_container(
                body,
                &nested_scope.package_name,
                nested_scope.module.clone(),
                nested_scope.class_unit.clone(),
                nested_scope.template_signature.clone(),
            );
        }
        if node.kind() == "enum_specifier" {
            self.visit_enum_enumerators(node, scope, &code_unit);
            if !self.has_enum_enumerator_units(&code_unit) {
                self.visit_enum_enumerators_from_text(node, scope, &code_unit);
            }
        }
    }

    fn has_enum_enumerator_units(&self, parent: &CodeUnit) -> bool {
        let prefix = format!("{}.", parent.short_name());
        self.parsed.declarations.iter().any(|unit| {
            unit.kind() == CodeUnitType::Field
                && unit.source() == parent.source()
                && unit.package_name() == parent.package_name()
                && unit.short_name().starts_with(&prefix)
        })
    }

    fn visit_enum_enumerators(&mut self, node: Node<'_>, scope: &ScopeInfo, parent: &CodeUnit) {
        if node.kind() == "enumerator_list" {
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                self.visit_enum_enumerators(child, scope, parent);
            }
            return;
        }
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            if child.kind() == "enumerator_list" {
                self.visit_enum_enumerators(child, scope, parent);
                continue;
            }
            if child.kind() != "enumerator" {
                continue;
            }
            let Some(name_node) = child.child_by_field_name("name") else {
                continue;
            };
            let name = normalize_cpp_whitespace(node_text(name_node, self.source));
            if name.is_empty() {
                continue;
            }
            let code_unit = CodeUnit::new(
                self.file.clone(),
                CodeUnitType::Field,
                scope.package_name.clone(),
                format!("{}.{}", parent.short_name(), name),
            );
            if self.parsed.declarations.contains(&code_unit) {
                continue;
            }
            self.parsed
                .add_code_unit(code_unit.clone(), child, self.source, None, None);
            self.parsed.add_signature(
                code_unit.clone(),
                normalize_cpp_whitespace(node_text(child, self.source)),
            );
            self.parsed.add_child(parent.clone(), code_unit);
        }
    }

    fn visit_enum_enumerators_from_text(
        &mut self,
        node: Node<'_>,
        scope: &ScopeInfo,
        parent: &CodeUnit,
    ) {
        let text = node_text(node, self.source);
        let Some((_, body)) = text.split_once('{') else {
            return;
        };
        let Some((body, _)) = body.rsplit_once('}') else {
            return;
        };
        for entry in body.split(',') {
            let trimmed = entry.trim();
            let name = trimmed
                .split('=')
                .next()
                .unwrap_or("")
                .split_whitespace()
                .next()
                .unwrap_or("");
            if name.is_empty() {
                continue;
            }
            let code_unit = CodeUnit::new(
                self.file.clone(),
                CodeUnitType::Field,
                scope.package_name.clone(),
                format!("{}.{}", parent.short_name(), name),
            );
            if self.parsed.declarations.contains(&code_unit) {
                continue;
            }
            self.parsed
                .add_code_unit(code_unit.clone(), node, self.source, None, None);
            self.parsed
                .add_signature(code_unit.clone(), trimmed.to_string());
            self.parsed.add_child(parent.clone(), code_unit);
        }
    }

    fn visit_function_definition(&mut self, node: Node<'_>, scope: &ScopeInfo) {
        let Some(declarator) = node.child_by_field_name("declarator") else {
            return;
        };
        let Some(function) = extract_function_info(declarator, self.source, scope) else {
            return;
        };
        let code_unit = function.code_unit(self.file.clone());
        self.parsed
            .replace_code_unit(code_unit.clone(), node, self.source, None, None);
        self.parsed.add_signature(
            code_unit.clone(),
            render_cpp_function_display_signature_from_node(
                node,
                self.source,
                scope.template_signature.as_deref(),
                true,
            ),
        );
        if let Some(parent) = &scope.class_unit {
            self.parsed.add_child(parent.clone(), code_unit);
        } else if let Some(module) = &scope.module {
            self.parsed.add_child(module.clone(), code_unit);
        }
    }

    fn visit_declaration(&mut self, node: Node<'_>, scope: &ScopeInfo, in_class_body: bool) {
        let mut handled_function = false;
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            if in_class_body
                && matches!(
                    child.kind(),
                    "class_specifier" | "struct_specifier" | "union_specifier" | "enum_specifier"
                )
            {
                self.visit_class_like(child, scope);
                continue;
            }
            if child.kind() == "function_declarator" {
                handled_function = true;
                self.visit_function_declaration(node, child, scope);
            } else if child.kind() == "init_declarator"
                && let Some(inner) = child.child_by_field_name("declarator")
            {
                if inner.kind() == "function_declarator" {
                    handled_function = true;
                    self.visit_function_declaration(node, inner, scope);
                } else {
                    self.visit_variable_declaration(node, inner, scope, in_class_body);
                }
            }
        }

        if handled_function {
            return;
        }

        if in_class_body {
            self.visit_class_members_from_declaration(node, scope);
        } else {
            self.visit_global_variables_from_declaration(node, scope);
        }
    }

    fn visit_function_declaration(
        &mut self,
        declaration_node: Node<'_>,
        declarator: Node<'_>,
        scope: &ScopeInfo,
    ) {
        let Some(function) = extract_function_info(declarator, self.source, scope) else {
            return;
        };
        let code_unit =
            function.code_unit_with_synthetic(self.file.clone(), scope.class_unit.is_some());
        if self.parsed.declarations.contains(&code_unit) {
            return;
        }
        self.parsed
            .add_code_unit(code_unit.clone(), declaration_node, self.source, None, None);
        self.parsed.add_signature(
            code_unit.clone(),
            render_cpp_function_display_signature_from_node(
                declaration_node,
                self.source,
                scope.template_signature.as_deref(),
                false,
            ),
        );
        if let Some(parent) = &scope.class_unit {
            self.parsed.add_child(parent.clone(), code_unit);
        } else if let Some(module) = &scope.module {
            self.parsed.add_child(module.clone(), code_unit);
        }
    }

    fn visit_variable_declaration(
        &mut self,
        declaration_node: Node<'_>,
        declarator: Node<'_>,
        scope: &ScopeInfo,
        in_class_body: bool,
    ) {
        let Some(name) = extract_variable_name(declarator, self.source) else {
            return;
        };
        let short_name = if in_class_body {
            let Some(parent) = &scope.class_unit else {
                return;
            };
            format!("{}.{}", parent.short_name(), name)
        } else {
            name
        };
        let code_unit = CodeUnit::new(
            self.file.clone(),
            CodeUnitType::Field,
            scope.package_name.clone(),
            short_name,
        );
        if self.parsed.declarations.contains(&code_unit) {
            return;
        }
        self.parsed
            .add_code_unit(code_unit.clone(), declaration_node, self.source, None, None);
        self.parsed.add_signature(
            code_unit.clone(),
            render_cpp_field_signature(declaration_node, declarator, self.source),
        );
        if let Some(parent) = &scope.class_unit {
            self.parsed.add_child(parent.clone(), code_unit);
        } else if let Some(module) = &scope.module {
            self.parsed.add_child(module.clone(), code_unit);
        }
    }

    fn visit_class_members_from_declaration(&mut self, node: Node<'_>, scope: &ScopeInfo) {
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            if child.kind() == "init_declarator"
                && let Some(inner) = child.child_by_field_name("declarator")
            {
                self.visit_variable_declaration(node, inner, scope, true);
            } else if matches!(
                child.kind(),
                "identifier"
                    | "field_identifier"
                    | "pointer_declarator"
                    | "reference_declarator"
                    | "array_declarator"
                    | "parenthesized_declarator"
            ) {
                self.visit_variable_declaration(node, child, scope, true);
            }
        }
    }

    fn visit_global_variables_from_declaration(&mut self, node: Node<'_>, scope: &ScopeInfo) {
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            if child.kind() == "init_declarator"
                && let Some(inner) = child.child_by_field_name("declarator")
            {
                self.visit_variable_declaration(node, inner, scope, false);
            } else if matches!(
                child.kind(),
                "identifier"
                    | "field_identifier"
                    | "pointer_declarator"
                    | "reference_declarator"
                    | "array_declarator"
                    | "parenthesized_declarator"
            ) {
                self.visit_variable_declaration(node, child, scope, false);
            }
        }
    }

    fn visit_include(&mut self, node: Node<'_>) {
        let raw = normalize_cpp_whitespace(node_text(node, self.source));
        self.parsed.import_statements.push(raw.clone());
        self.parsed.imports.push(ImportInfo {
            raw_snippet: raw,
            is_wildcard: false,
            identifier: None,
            alias: None,
        });
    }
}

#[derive(Clone)]
struct FunctionInfo {
    package_name: String,
    owner_path: Option<String>,
    name: String,
    signature: String,
}

impl FunctionInfo {
    fn code_unit(&self, file: ProjectFile) -> CodeUnit {
        self.code_unit_with_synthetic(file, false)
    }

    fn code_unit_with_synthetic(&self, file: ProjectFile, synthetic: bool) -> CodeUnit {
        let short_name = if let Some(owner) = &self.owner_path {
            format!("{owner}.{}", self.name)
        } else {
            self.name.clone()
        };
        CodeUnit::with_signature(
            file,
            CodeUnitType::Function,
            self.package_name.clone(),
            short_name,
            Some(self.signature.clone()),
            synthetic,
        )
    }
}

fn extract_function_info(
    declarator: Node<'_>,
    source: &str,
    scope: &ScopeInfo,
) -> Option<FunctionInfo> {
    let parameters_node = declarator.child_by_field_name("parameters")?;
    let parameters_text = cpp_parameter_signature(parameters_node, source);
    let declarator_name_node = declarator
        .child_by_field_name("declarator")
        .or_else(|| last_named_child(declarator))?;
    let raw_name = normalize_cpp_whitespace(&extract_declarator_name(declarator_name_node, source));
    if raw_name.is_empty() {
        return None;
    }

    let (owner_path, name, package_name) = split_cpp_name(&raw_name, scope);
    let full_text = normalize_cpp_whitespace(node_text(declarator, source));
    let suffix = full_text
        .split_once(node_text(parameters_node, source))
        .map(|(_, tail)| normalize_cpp_qualifier_suffix(tail))
        .unwrap_or_default();
    let mut signature = if suffix.is_empty() {
        parameters_text
    } else {
        format!("{parameters_text} {suffix}")
    };
    if let Some(template_signature) = &scope.template_signature {
        signature = format!("{template_signature}{signature}");
    }

    Some(FunctionInfo {
        package_name,
        owner_path,
        name,
        signature,
    })
}

fn split_cpp_name(raw_name: &str, scope: &ScopeInfo) -> (Option<String>, String, String) {
    let cleaned = raw_name.trim_start_matches("template ").trim();
    let parts: Vec<_> = cleaned.split("::").collect();
    if parts.len() > 1 {
        let name = parts.last().unwrap_or(&cleaned).to_string();
        let owner_parts = &parts[..parts.len() - 1];
        let mut package_name = scope.package_name.clone();
        let owner_path = if let Some(class_unit) = &scope.class_unit {
            Some(class_unit.short_name().to_string())
        } else if owner_parts.len() > 1 {
            package_name = if package_name.is_empty() {
                owner_parts[..owner_parts.len() - 1].join("::")
            } else {
                package_name
            };
            Some(owner_parts.last().unwrap_or(&"").to_string())
        } else {
            Some(owner_parts[0].to_string())
        };
        return (owner_path, name, package_name);
    }

    let package_name = scope.package_name.clone();
    let owner_path = scope
        .class_unit
        .as_ref()
        .map(|parent| parent.short_name().to_string());
    (owner_path, cleaned.to_string(), package_name)
}

fn extract_declarator_name(node: Node<'_>, source: &str) -> String {
    match node.kind() {
        "identifier"
        | "field_identifier"
        | "type_identifier"
        | "operator_name"
        | "destructor_name"
        | "qualified_identifier" => node_text(node, source).to_string(),
        "function_declarator"
        | "pointer_declarator"
        | "reference_declarator"
        | "parenthesized_declarator"
        | "array_declarator"
        | "template_function" => node
            .child_by_field_name("declarator")
            .or_else(|| node.child_by_field_name("name"))
            .or_else(|| last_named_child(node))
            .map(|child| extract_declarator_name(child, source))
            .unwrap_or_else(|| node_text(node, source).to_string()),
        _ => node
            .child_by_field_name("name")
            .map(|child| extract_declarator_name(child, source))
            .unwrap_or_else(|| node_text(node, source).to_string()),
    }
}

fn extract_variable_name(node: Node<'_>, source: &str) -> Option<String> {
    match node.kind() {
        "identifier" | "field_identifier" => {
            let name = node_text(node, source).trim().to_string();
            (!name.is_empty()).then_some(name)
        }
        _ => node
            .child_by_field_name("declarator")
            .or_else(|| node.child_by_field_name("name"))
            .or_else(|| last_named_child(node))
            .and_then(|child| extract_variable_name(child, source)),
    }
}

fn last_named_child(node: Node<'_>) -> Option<Node<'_>> {
    let count = node.named_child_count();
    if count == 0 {
        None
    } else {
        node.named_child(count - 1)
    }
}

fn render_cpp_type_signature(
    node: Node<'_>,
    source: &str,
    template_signature: Option<&str>,
) -> String {
    let text = normalize_cpp_whitespace(node_text(node, source));
    let head = text.split('{').next().unwrap_or(text.as_str()).trim();
    let rendered = if head.ends_with(';') {
        head.to_string()
    } else {
        format!("{head} {{")
    };
    if let Some(template_signature) = template_signature {
        format!("template {template_signature} {rendered}")
    } else {
        rendered
    }
}

fn render_cpp_field_signature(node: Node<'_>, declarator: Node<'_>, source: &str) -> String {
    let declaration_text = normalize_cpp_whitespace(node_text(node, source));
    let prefix = cpp_declaration_prefix(node, source);
    let name = extract_variable_name(declarator, source).unwrap_or_default();
    let raw_suffix = cpp_declarator_suffix_without_name(declarator, source);
    let suffix = if (prefix.ends_with('*') && raw_suffix == "*")
        || (prefix.ends_with('&') && raw_suffix == "&")
    {
        String::new()
    } else {
        raw_suffix
    };

    let mut rendered = if suffix.is_empty() {
        format!("{prefix} {name}")
    } else if suffix.starts_with('*') || suffix.starts_with('&') {
        format!("{prefix}{suffix} {name}")
    } else if suffix.starts_with('[') || suffix.starts_with('(') {
        format!("{prefix} {name}{suffix}")
    } else {
        format!("{prefix} {suffix}{name}")
    };
    rendered = collapse_cpp_whitespace(&rendered);

    if let Some(initializer) = cpp_preserved_initializer(node, declarator, source) {
        format!("{rendered} = {initializer};")
    } else if declaration_text.ends_with(';') {
        format!("{rendered};")
    } else {
        rendered
    }
}

fn cpp_declaration_prefix(node: Node<'_>, source: &str) -> String {
    let text = node_text(node, source);
    let mut cursor = node.walk();
    let first_declarator = node.named_children(&mut cursor).find(|child| {
        matches!(
            child.kind(),
            "init_declarator"
                | "identifier"
                | "field_identifier"
                | "pointer_declarator"
                | "reference_declarator"
                | "array_declarator"
                | "function_declarator"
        )
    });
    let prefix = if let Some(first_declarator) = first_declarator {
        let end = first_declarator
            .start_byte()
            .saturating_sub(node.start_byte());
        let mut prefix = text.get(..end).unwrap_or(text).to_string();
        let declarator_suffix = match first_declarator.kind() {
            "init_declarator" => first_declarator
                .child_by_field_name("declarator")
                .map(|inner| cpp_declarator_suffix_without_name(inner, source))
                .unwrap_or_default(),
            _ => cpp_declarator_suffix_without_name(first_declarator, source),
        };
        if declarator_suffix.starts_with('*') || declarator_suffix.starts_with('&') {
            prefix.push_str(&declarator_suffix);
        }
        return collapse_cpp_whitespace(&prefix)
            .trim_end_matches(',')
            .trim_end_matches(';')
            .trim()
            .to_string();
    } else {
        text
    };
    collapse_cpp_whitespace(prefix)
        .trim_end_matches(',')
        .trim_end_matches(';')
        .trim()
        .to_string()
}

fn cpp_preserved_initializer(
    declaration_node: Node<'_>,
    declarator: Node<'_>,
    source: &str,
) -> Option<String> {
    let name = extract_variable_name(declarator, source)?;
    let mut cursor = declaration_node.walk();
    for child in declaration_node.named_children(&mut cursor) {
        if child.kind() != "init_declarator" {
            continue;
        }
        let Some(inner) = child.child_by_field_name("declarator") else {
            continue;
        };
        if extract_variable_name(inner, source).as_deref() != Some(name.as_str()) {
            continue;
        }
        let value = child.child_by_field_name("value")?;
        let kind = value.kind();
        if matches!(
            kind,
            "number_literal" | "float_literal" | "char_literal" | "true" | "false"
        ) {
            return Some(normalize_cpp_whitespace(node_text(value, source)));
        }
        break;
    }
    let declaration_text = normalize_cpp_whitespace(node_text(declaration_node, source));
    let pattern = format!(
        r"\b{}\s*=\s*([-+]?[0-9]+(?:\.[0-9]+)?)",
        regex::escape(&name)
    );
    Regex::new(&pattern)
        .ok()
        .and_then(|regex| regex.captures(&declaration_text))
        .and_then(|captures| captures.get(1))
        .map(|value| value.as_str().to_string())
}

fn render_cpp_function_display_signature_from_node(
    node: Node<'_>,
    source: &str,
    template_signature: Option<&str>,
    has_body: bool,
) -> String {
    let root = enclosing_cpp_declaration_node(node).unwrap_or(node);
    let parent_text = node_text(root, source);
    let body_local_start = root
        .child_by_field_name("body")
        .map(|body| body.start_byte().saturating_sub(root.start_byte()))
        .unwrap_or(parent_text.len());
    let display = parent_text
        .get(..body_local_start)
        .unwrap_or(parent_text)
        .trim()
        .trim();
    let display = if let Some(template_signature) = template_signature {
        if display.starts_with("template ") {
            display.to_string()
        } else {
            format!("template {template_signature} {display}")
        }
    } else {
        display.to_string()
    };
    let display = collapse_cpp_whitespace(display.trim_end_matches(';'));
    if has_body {
        format!("{display} {{...}}")
    } else {
        format!("{display};")
    }
}

fn cpp_template_signature(
    template_node: Node<'_>,
    declaration_child: Node<'_>,
    source: &str,
) -> Option<String> {
    let text = source
        .get(template_node.start_byte()..declaration_child.start_byte())
        .unwrap_or("");
    let text = normalize_cpp_whitespace(text);
    let start = text.find('<')?;
    let end = text.rfind('>')?;
    if end < start {
        return None;
    }
    Some(text[start..=end].to_string())
}

fn enclosing_cpp_declaration_node(mut node: Node<'_>) -> Option<Node<'_>> {
    loop {
        match node.kind() {
            "declaration"
            | "function_declaration"
            | "field_declaration"
            | "function_definition" => return Some(node),
            _ => node = node.parent()?,
        }
    }
}

fn cpp_parameter_signature(parameters_node: Node<'_>, source: &str) -> String {
    let mut params = Vec::new();
    let mut cursor = parameters_node.walk();
    for child in parameters_node.named_children(&mut cursor) {
        match child.kind() {
            "parameter_declaration" | "optional_parameter_declaration" => {
                params.push(cpp_parameter_type(child, source));
            }
            "variadic_parameter" => params.push("...".to_string()),
            _ => {}
        }
    }

    if params.is_empty() {
        "()".to_string()
    } else {
        format!("({})", params.join(", "))
    }
}

fn cpp_parameter_type(parameter: Node<'_>, source: &str) -> String {
    let type_text = parameter
        .child_by_field_name("type")
        .map(|node| normalize_cpp_whitespace(node_text(node, source)))
        .unwrap_or_default();
    let declarator_suffix = parameter
        .child_by_field_name("declarator")
        .map(|node| cpp_declarator_suffix_without_name(node, source))
        .unwrap_or_default();

    let combined = if type_text.is_empty() {
        declarator_suffix
    } else if declarator_suffix.is_empty() {
        type_text
    } else {
        format!("{type_text} {declarator_suffix}")
    };
    normalize_cpp_type_text(&combined)
}

fn cpp_declarator_suffix_without_name(node: Node<'_>, source: &str) -> String {
    match node.kind() {
        "identifier" | "field_identifier" => String::new(),
        "pointer_declarator" => {
            let inner = node
                .child_by_field_name("declarator")
                .or_else(|| last_named_child(node))
                .map(|child| cpp_declarator_suffix_without_name(child, source))
                .unwrap_or_default();
            format!("*{inner}")
        }
        "reference_declarator" => {
            let inner = node
                .child_by_field_name("declarator")
                .or_else(|| last_named_child(node))
                .map(|child| cpp_declarator_suffix_without_name(child, source))
                .unwrap_or_default();
            format!("&{inner}")
        }
        "array_declarator" => {
            let inner = node
                .child_by_field_name("declarator")
                .map(|child| cpp_declarator_suffix_without_name(child, source))
                .unwrap_or_default();
            let size = node
                .child_by_field_name("size")
                .map(|child| normalize_cpp_whitespace(node_text(child, source)))
                .unwrap_or_default();
            format!("{inner}[{size}]")
        }
        "parenthesized_declarator" => node
            .child_by_field_name("declarator")
            .or_else(|| last_named_child(node))
            .map(|child| format!("({})", cpp_declarator_suffix_without_name(child, source)))
            .unwrap_or_default(),
        "function_declarator" => {
            let inner = node
                .child_by_field_name("declarator")
                .map(|child| cpp_declarator_suffix_without_name(child, source))
                .unwrap_or_default();
            let params = node
                .child_by_field_name("parameters")
                .map(|child| cpp_parameter_signature(child, source))
                .unwrap_or_else(|| "()".to_string());
            format!("{inner}{params}")
        }
        _ => {
            let text = normalize_cpp_whitespace(node_text(node, source));
            let name = extract_declarator_name(node, source);
            if name.is_empty() {
                text
            } else {
                text.replace(&name, "").trim().to_string()
            }
        }
    }
}

fn normalize_cpp_qualifier_suffix(suffix: &str) -> String {
    collapse_cpp_whitespace(
        suffix
            .trim()
            .trim_start_matches("->")
            .trim_start_matches('{')
            .trim_end_matches(';'),
    )
}

pub(crate) fn normalize_cpp_whitespace(value: &str) -> String {
    collapse_cpp_whitespace(value)
}

fn normalize_cpp_type_text(value: &str) -> String {
    collapse_cpp_whitespace(value)
        .replace(", ", ",")
        .replace(" <", "<")
        .replace("< ", "<")
        .replace(" >", ">")
}

fn collapse_cpp_whitespace(value: &str) -> String {
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

pub(crate) fn node_text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    source.get(node.start_byte()..node.end_byte()).unwrap_or("")
}

pub(super) fn collect_cpp_identifiers(
    node: Node<'_>,
    source: &str,
    identifiers: &mut HashSet<String>,
) {
    match node.kind() {
        "type_identifier" | "identifier" | "qualified_identifier" => {
            let text = node_text(node, source).trim();
            if !text.is_empty() {
                identifiers.insert(text.to_string());
            }
        }
        _ => {}
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        collect_cpp_identifiers(child, source, identifiers);
    }
}

fn cpp_body_node(node: Node<'_>) -> Option<Node<'_>> {
    node.child_by_field_name("body").or_else(|| {
        let mut cursor = node.walk();
        node.named_children(&mut cursor).find(|child| {
            matches!(
                child.kind(),
                "declaration_list" | "field_declaration_list" | "enumerator_list"
            )
        })
    })
}
