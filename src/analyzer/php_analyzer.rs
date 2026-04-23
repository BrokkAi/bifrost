use crate::analyzer::{
    AnalyzerConfig, CodeUnit, CodeUnitType, IAnalyzer, Language, LanguageAdapter, Project,
    ProjectFile, Range, TestDetectionProvider, TreeSitterAnalyzer,
};
use regex::Regex;
use std::collections::BTreeSet;
use std::sync::Arc;
use tree_sitter::{Language as TsLanguage, Node, Point, Tree};

#[derive(Debug, Clone, Default)]
pub struct PhpAdapter;

impl LanguageAdapter for PhpAdapter {
    fn language(&self) -> Language {
        Language::Php
    }

    fn query_directory(&self) -> &'static str {
        "resources/treesitter/php"
    }

    fn parser_language(&self) -> TsLanguage {
        tree_sitter_php::LANGUAGE_PHP.into()
    }

    fn file_extension(&self) -> &'static str {
        "php"
    }

    fn contains_tests(
        &self,
        _file: &ProjectFile,
        source: &str,
        _tree: &Tree,
        parsed: &crate::analyzer::tree_sitter_analyzer::ParsedFile,
    ) -> bool {
        php_contains_tests(source, parsed)
    }

    fn extract_call_receiver(&self, reference: &str) -> Option<String> {
        let trimmed = reference.trim();
        let before_args = trimmed
            .split_once('(')
            .map(|(head, _)| head)
            .unwrap_or(trimmed);
        before_args
            .rsplit_once("::")
            .or_else(|| before_args.rsplit_once("->"))
            .map(|(receiver, _)| receiver.to_string())
    }

    fn parse_file(
        &self,
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
}

#[derive(Clone)]
pub struct PhpAnalyzer {
    inner: TreeSitterAnalyzer<PhpAdapter>,
}

impl PhpAnalyzer {
    pub fn new(project: Arc<dyn Project>) -> Self {
        Self::new_with_config(project, AnalyzerConfig::default())
    }

    pub fn new_with_config(project: Arc<dyn Project>, config: AnalyzerConfig) -> Self {
        Self {
            inner: TreeSitterAnalyzer::new_with_config(project, PhpAdapter, config),
        }
    }

    pub fn from_project<P>(project: P) -> Self
    where
        P: Project + 'static,
    {
        Self::new(Arc::new(project))
    }

    pub fn is_constructor(
        &self,
        method: &CodeUnit,
        class_unit: &CodeUnit,
        _package_name: &str,
    ) -> bool {
        method.is_function()
            && class_unit.is_class()
            && method.identifier() == "__construct"
            && method.fq_name() == format!("{}.__construct", class_unit.fq_name())
    }
}

impl TestDetectionProvider for PhpAnalyzer {}

impl IAnalyzer for PhpAnalyzer {
    fn top_level_declarations<'a>(
        &'a self,
        file: &ProjectFile,
    ) -> Box<dyn Iterator<Item = &'a CodeUnit> + 'a> {
        self.inner.top_level_declarations(file)
    }

    fn analyzed_files<'a>(&'a self) -> Box<dyn Iterator<Item = &'a ProjectFile> + 'a> {
        self.inner.analyzed_files()
    }

    fn all_declarations<'a>(&'a self) -> Box<dyn Iterator<Item = &'a CodeUnit> + 'a> {
        self.inner.all_declarations()
    }

    fn declarations<'a>(
        &'a self,
        file: &ProjectFile,
    ) -> Box<dyn Iterator<Item = &'a CodeUnit> + 'a> {
        self.inner.declarations(file)
    }

    fn definitions<'a>(&'a self, fq_name: &'a str) -> Box<dyn Iterator<Item = &'a CodeUnit> + 'a> {
        self.inner.definitions(fq_name)
    }

    fn direct_children<'a>(
        &'a self,
        code_unit: &CodeUnit,
    ) -> Box<dyn Iterator<Item = &'a CodeUnit> + 'a> {
        self.inner.direct_children(code_unit)
    }

    fn import_statements<'a>(&'a self, file: &ProjectFile) -> &'a [String] {
        self.inner.import_statements(file)
    }

    fn ranges<'a>(&'a self, code_unit: &CodeUnit) -> &'a [crate::analyzer::Range] {
        self.inner.ranges(code_unit)
    }

    fn signatures<'a>(&'a self, code_unit: &CodeUnit) -> &'a [String] {
        self.inner.signatures(code_unit)
    }

    fn get_top_level_declarations(&self, file: &ProjectFile) -> Vec<CodeUnit> {
        self.inner.get_top_level_declarations(file)
    }

    fn get_analyzed_files(&self) -> BTreeSet<ProjectFile> {
        self.inner.get_analyzed_files()
    }

    fn languages(&self) -> BTreeSet<Language> {
        self.inner.languages()
    }

    fn update(&self, changed_files: &BTreeSet<ProjectFile>) -> Self {
        Self {
            inner: self.inner.update(changed_files),
        }
    }

    fn update_all(&self) -> Self {
        Self {
            inner: self.inner.update_all(),
        }
    }

    fn project(&self) -> &dyn Project {
        self.inner.project()
    }

    fn get_all_declarations(&self) -> Vec<CodeUnit> {
        self.inner.get_all_declarations()
    }

    fn get_declarations(&self, file: &ProjectFile) -> BTreeSet<CodeUnit> {
        self.inner.get_declarations(file)
    }

    fn get_definitions(&self, fq_name: &str) -> Vec<CodeUnit> {
        self.inner.get_definitions(fq_name)
    }

    fn get_direct_children(&self, code_unit: &CodeUnit) -> Vec<CodeUnit> {
        self.inner.get_direct_children(code_unit)
    }

    fn extract_call_receiver(&self, reference: &str) -> Option<String> {
        self.inner.extract_call_receiver(reference)
    }

    fn import_statements_of(&self, file: &ProjectFile) -> Vec<String> {
        self.inner.import_statements_of(file)
    }

    fn enclosing_code_unit(&self, file: &ProjectFile, range: &Range) -> Option<CodeUnit> {
        self.inner.enclosing_code_unit(file, range)
    }

    fn enclosing_code_unit_for_lines(
        &self,
        file: &ProjectFile,
        start_line: usize,
        end_line: usize,
    ) -> Option<CodeUnit> {
        self.inner
            .enclosing_code_unit_for_lines(file, start_line, end_line)
    }

    fn is_access_expression(&self, file: &ProjectFile, start_byte: usize, end_byte: usize) -> bool {
        self.inner.is_access_expression(file, start_byte, end_byte)
    }

    fn find_nearest_declaration(
        &self,
        file: &ProjectFile,
        start_byte: usize,
        end_byte: usize,
        ident: &str,
    ) -> Option<crate::analyzer::DeclarationInfo> {
        self.inner
            .find_nearest_declaration(file, start_byte, end_byte, ident)
    }

    fn ranges_of(&self, code_unit: &CodeUnit) -> Vec<Range> {
        self.inner.ranges_of(code_unit)
    }

    fn get_skeleton(&self, code_unit: &CodeUnit) -> Option<String> {
        let skeleton = self.inner.get_skeleton(code_unit)?;
        if code_unit.is_class() && self.inner.direct_children(code_unit).next().is_none() {
            let trimmed = skeleton.trim();
            if trimmed.ends_with("{\n}") || trimmed.ends_with("{\r\n}") {
                let compact = trimmed.trim_end_matches('}').trim_end().to_string();
                return Some(format!("{compact} }}"));
            }
        }
        Some(skeleton)
    }

    fn get_skeleton_header(&self, code_unit: &CodeUnit) -> Option<String> {
        self.inner.get_skeleton_header(code_unit)
    }

    fn get_source(&self, code_unit: &CodeUnit, include_comments: bool) -> Option<String> {
        self.inner.get_source(code_unit, include_comments)
    }

    fn get_sources(&self, code_unit: &CodeUnit, include_comments: bool) -> BTreeSet<String> {
        self.inner.get_sources(code_unit, include_comments)
    }

    fn search_definitions(&self, pattern: &str, auto_quote: bool) -> BTreeSet<CodeUnit> {
        self.inner.search_definitions(pattern, auto_quote)
    }

    fn signatures_of(&self, code_unit: &CodeUnit) -> Vec<String> {
        self.inner.signatures_of(code_unit).to_vec()
    }

    fn contains_tests(&self, file: &ProjectFile) -> bool {
        self.inner.contains_tests(file)
    }

    fn test_detection_provider(&self) -> Option<&dyn TestDetectionProvider> {
        Some(self)
    }
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

struct PhpVisitor<'a> {
    file: &'a ProjectFile,
    source: &'a str,
    parsed: &'a mut crate::analyzer::tree_sitter_analyzer::ParsedFile,
}

impl<'a> PhpVisitor<'a> {
    fn visit_children(&mut self, node: Node<'_>, scope: &PhpScope) {
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            self.visit_node(child, scope);
        }
    }

    fn visit_node(&mut self, node: Node<'_>, scope: &PhpScope) {
        match node.kind() {
            "namespace_definition" => self.visit_namespace(node, scope),
            "class_declaration" | "interface_declaration" | "trait_declaration" => {
                self.visit_type_declaration(node, scope)
            }
            "function_definition" => self.visit_function(node, scope),
            "method_declaration" => self.visit_method(node, scope),
            "property_declaration" => self.visit_property_declaration(node, scope),
            "const_declaration" => self.visit_const_declaration(node, scope),
            "declaration_list" | "compound_statement" => self.visit_children(node, scope),
            _ => {}
        }
    }

    fn visit_namespace(&mut self, node: Node<'_>, scope: &PhpScope) {
        let Some(name_node) = node.child_by_field_name("name") else {
            return;
        };
        let package_name = php_node_text(name_node, self.source).replace('\\', ".");
        let scope = PhpScope::new(package_name, scope.class_unit.clone());
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            match child.kind() {
                "namespace_name" | "name" => {}
                _ => self.visit_node(child, &scope),
            }
        }
    }

    fn visit_type_declaration(&mut self, node: Node<'_>, scope: &PhpScope) {
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

        if let Some(body) = php_class_body(node) {
            self.visit_children(
                body,
                &PhpScope::new(scope.package_name.clone(), Some(code_unit)),
            );
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

fn php_contains_tests(
    source: &str,
    parsed: &crate::analyzer::tree_sitter_analyzer::ParsedFile,
) -> bool {
    if parsed.declarations.iter().any(|code_unit| {
        let lower = code_unit.identifier().to_ascii_lowercase();
        (code_unit.is_class() && lower.contains("test"))
            || (code_unit.is_function() && lower.starts_with("test"))
    }) {
        return true;
    }

    static DOCBLOCK_TEST_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
        Regex::new(
            r"(?is)/\*\*.*?@test.*?\*/\s*(?:(?:public|protected|private|static|final|abstract|readonly)\s+)*function\b",
        )
        .unwrap()
    });
    DOCBLOCK_TEST_RE.is_match(source)
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
    if node.kind() == kind {
        return Some(node);
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if let Some(found) = php_find_named_descendant(child, kind) {
            return Some(found);
        }
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
