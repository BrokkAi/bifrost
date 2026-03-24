use crate::analyzer::{
    CodeUnit, IAnalyzer, ImportAnalysisProvider, ImportInfo, Language, LanguageAdapter, Project,
    ProjectFile, TreeSitterAnalyzer, TypeHierarchyProvider,
};
use std::collections::BTreeSet;
use std::sync::Arc;
use tree_sitter::{Language as TsLanguage, Node, Tree};

#[derive(Debug, Clone, Default)]
pub struct JavaAdapter;

impl LanguageAdapter for JavaAdapter {
    fn language(&self) -> Language {
        Language::Java
    }

    fn query_directory(&self) -> &'static str {
        "resources/treesitter/java"
    }

    fn parser_language(&self) -> TsLanguage {
        tree_sitter_java::LANGUAGE.into()
    }

    fn file_extension(&self) -> &'static str {
        "java"
    }

    fn normalize_full_name(&self, fq_name: &str) -> String {
        fq_name.replace('$', ".")
    }

    fn extract_call_receiver(&self, reference: &str) -> Option<String> {
        reference.rsplit_once('.').map(|(left, _)| left.to_string())
    }

    fn parse_file(
        &self,
        file: &ProjectFile,
        source: &str,
        tree: &Tree,
    ) -> crate::analyzer::tree_sitter_analyzer::ParsedFile {
        let root = tree.root_node();
        let package_name = determine_package_name(root, source);
        let mut parsed = crate::analyzer::tree_sitter_analyzer::ParsedFile::new(package_name.clone());

        for index in 0..root.named_child_count() {
            let Some(child) = root.named_child(index) else {
                continue;
            };

            match child.kind() {
                "import_declaration" => {
                    let raw = node_text(child, source).trim().to_string();
                    parsed.import_statements.push(raw.clone());
                    parsed.imports.push(parse_import_info(raw));
                }
                "class_declaration"
                | "interface_declaration"
                | "enum_declaration"
                | "record_declaration"
                | "annotation_type_declaration" => {
                    visit_class_like(
                        file,
                        source,
                        child,
                        &package_name,
                        None,
                        None,
                        &mut parsed,
                    );
                }
                _ => {}
            }
        }

        parsed
    }
}

#[derive(Clone)]
pub struct JavaAnalyzer {
    inner: TreeSitterAnalyzer<JavaAdapter>,
}

impl JavaAnalyzer {
    pub fn new(project: Arc<dyn Project>) -> Self {
        Self {
            inner: TreeSitterAnalyzer::new(project, JavaAdapter),
        }
    }

    pub fn from_project<P>(project: P) -> Self
    where
        P: Project + 'static,
    {
        Self::new(Arc::new(project))
    }

    pub fn inner(&self) -> &TreeSitterAnalyzer<JavaAdapter> {
        &self.inner
    }
}

impl ImportAnalysisProvider for JavaAnalyzer {
    fn imported_code_units_of(&self, file: &ProjectFile) -> BTreeSet<CodeUnit> {
        let mut resolved = BTreeSet::new();

        for import in self.inner.import_info_of(file) {
            if import.raw_snippet.trim_start().starts_with("import static ") {
                continue;
            }

            let import_path = import
                .raw_snippet
                .trim()
                .strip_prefix("import ")
                .unwrap_or(import.raw_snippet.trim())
                .strip_suffix(';')
                .unwrap_or(import.raw_snippet.trim())
                .trim();

            if import.is_wildcard {
                let package_name = import_path.trim_end_matches(".*");
                for code_unit in self.inner.get_all_declarations() {
                    if code_unit.is_class() && code_unit.package_name() == package_name {
                        resolved.insert(code_unit);
                    }
                }
                continue;
            }

            for code_unit in self.inner.get_definitions(import_path) {
                resolved.insert(code_unit);
            }
        }

        resolved
    }

    fn referencing_files_of(&self, file: &ProjectFile) -> BTreeSet<ProjectFile> {
        self.inner
            .get_analyzed_files()
            .into_iter()
            .filter(|candidate| {
                self.imported_code_units_of(candidate)
                    .into_iter()
                    .any(|code_unit| code_unit.source() == file)
            })
            .collect()
    }

    fn import_info_of(&self, file: &ProjectFile) -> Vec<ImportInfo> {
        self.inner.import_info_of(file)
    }

    fn could_import_file(&self, source_file: &ProjectFile, imports: &[ImportInfo], target: &ProjectFile) -> bool {
        if source_file == target {
            return false;
        }

        let source_package = self.inner.package_name_of(source_file).unwrap_or("");
        let target_package = self.inner.package_name_of(target).unwrap_or("");
        if !source_package.is_empty() && source_package == target_package {
            return true;
        }

        let temp_file = ProjectFile::new(source_file.root().to_path_buf(), source_file.rel_path().to_path_buf());
        let _ = temp_file;

        imports.iter().any(|import| {
            let raw = import
                .raw_snippet
                .trim()
                .strip_prefix("import ")
                .unwrap_or(import.raw_snippet.trim())
                .strip_suffix(';')
                .unwrap_or(import.raw_snippet.trim())
                .trim();

            if raw.ends_with(".*") {
                let import_package = raw.trim_end_matches(".*");
                return self.inner.package_name_of(target) == Some(import_package);
            }

            self.inner
                .get_definitions(raw)
                .into_iter()
                .any(|code_unit| code_unit.source() == target)
        })
    }
}

fn determine_package_name(root: Node<'_>, source: &str) -> String {
    for index in 0..root.named_child_count() {
        let Some(child) = root.named_child(index) else {
            continue;
        };

        if child.kind() == "package_declaration" {
            return node_text(child, source)
                .trim()
                .strip_prefix("package ")
                .unwrap_or("")
                .strip_suffix(';')
                .unwrap_or("")
                .trim()
                .to_string();
        }

        if matches!(
            child.kind(),
            "class_declaration"
                | "interface_declaration"
                | "enum_declaration"
                | "record_declaration"
                | "annotation_type_declaration"
        ) {
            break;
        }
    }

    String::new()
}

fn parse_import_info(raw: String) -> ImportInfo {
    let trimmed = raw
        .trim()
        .strip_prefix("import ")
        .unwrap_or(raw.trim())
        .strip_suffix(';')
        .unwrap_or(raw.trim())
        .trim();
    let trimmed = trimmed.strip_prefix("static ").unwrap_or(trimmed).trim();
    let is_wildcard = trimmed.ends_with(".*");
    let identifier = (!is_wildcard)
        .then(|| trimmed.rsplit('.').next().map(str::to_string))
        .flatten();

    ImportInfo {
        raw_snippet: raw,
        is_wildcard,
        identifier,
        alias: None,
    }
}

fn visit_class_like(
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    package_name: &str,
    parent: Option<&CodeUnit>,
    top_level_owner: Option<&CodeUnit>,
    parsed: &mut crate::analyzer::tree_sitter_analyzer::ParsedFile,
) {
    let Some(name_node) = node.child_by_field_name("name") else {
        return;
    };

    let simple_name = node_text(name_node, source).trim().to_string();
    if simple_name.is_empty() {
        return;
    }

    let short_name = parent
        .map(|parent| format!("{}.{}", parent.short_name(), simple_name))
        .unwrap_or(simple_name.clone());

    let code_unit = CodeUnit::new(
        file.clone(),
        crate::analyzer::CodeUnitType::Class,
        package_name.to_string(),
        short_name,
    );

    let top_level = top_level_owner.cloned().unwrap_or_else(|| code_unit.clone());
    parsed.add_code_unit(
        code_unit.clone(),
        node,
        source,
        parent.cloned(),
        Some(top_level.clone()),
    );

    if let Some(body) = node.child_by_field_name("body") {
        for index in 0..body.named_child_count() {
            let Some(child) = body.named_child(index) else {
                continue;
            };

            match child.kind() {
                "class_declaration"
                | "interface_declaration"
                | "enum_declaration"
                | "record_declaration"
                | "annotation_type_declaration" => {
                    visit_class_like(
                        file,
                        source,
                        child,
                        package_name,
                        Some(&code_unit),
                        Some(&top_level),
                        parsed,
                    );
                }
                "method_declaration" | "constructor_declaration" => {
                    visit_callable(file, source, child, package_name, &code_unit, &top_level, parsed);
                }
                "field_declaration" | "constant_declaration" => {
                    visit_field_declaration(
                        file,
                        source,
                        child,
                        package_name,
                        &code_unit,
                        &top_level,
                        parsed,
                    );
                }
                "enum_constant" => {
                    visit_enum_constant(
                        file,
                        source,
                        child,
                        package_name,
                        &code_unit,
                        &top_level,
                        parsed,
                    );
                }
                _ => {}
            }
        }
    }
}

fn visit_callable(
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    package_name: &str,
    parent: &CodeUnit,
    top_level: &CodeUnit,
    parsed: &mut crate::analyzer::tree_sitter_analyzer::ParsedFile,
) {
    let Some(name_node) = node.child_by_field_name("name") else {
        return;
    };

    let name = node_text(name_node, source).trim();
    if name.is_empty() {
        return;
    }

    let signature = node
        .child_by_field_name("parameters")
        .map(|parameters| normalize_whitespace(node_text(parameters, source)));
    let short_name = format!("{}.{}", parent.short_name(), name);
    let code_unit = CodeUnit::with_signature(
        file.clone(),
        crate::analyzer::CodeUnitType::Function,
        package_name.to_string(),
        short_name,
        signature,
        false,
    );

    parsed.add_code_unit(code_unit, node, source, Some(parent.clone()), Some(top_level.clone()));
}

fn visit_field_declaration(
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    package_name: &str,
    parent: &CodeUnit,
    top_level: &CodeUnit,
    parsed: &mut crate::analyzer::tree_sitter_analyzer::ParsedFile,
) {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.kind() != "variable_declarator" {
            continue;
        }

        let Some(name_node) = child.child_by_field_name("name") else {
            continue;
        };

        let name = node_text(name_node, source).trim();
        if name.is_empty() {
            continue;
        }

        let code_unit = CodeUnit::new(
            file.clone(),
            crate::analyzer::CodeUnitType::Field,
            package_name.to_string(),
            format!("{}.{}", parent.short_name(), name),
        );
        parsed.add_code_unit(code_unit, node, source, Some(parent.clone()), Some(top_level.clone()));
    }
}

fn visit_enum_constant(
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    package_name: &str,
    parent: &CodeUnit,
    top_level: &CodeUnit,
    parsed: &mut crate::analyzer::tree_sitter_analyzer::ParsedFile,
) {
    let Some(name_node) = node.child_by_field_name("name") else {
        return;
    };

    let name = node_text(name_node, source).trim();
    if name.is_empty() {
        return;
    }

    let code_unit = CodeUnit::new(
        file.clone(),
        crate::analyzer::CodeUnitType::Field,
        package_name.to_string(),
        format!("{}.{}", parent.short_name(), name),
    );
    parsed.add_code_unit(code_unit, node, source, Some(parent.clone()), Some(top_level.clone()));
}

fn node_text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    source.get(node.start_byte()..node.end_byte()).unwrap_or("")
}

fn normalize_whitespace(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

impl TypeHierarchyProvider for JavaAnalyzer {
    fn get_direct_ancestors(&self, _code_unit: &CodeUnit) -> Vec<CodeUnit> {
        Vec::new()
    }

    fn get_direct_descendants(&self, _code_unit: &CodeUnit) -> BTreeSet<CodeUnit> {
        BTreeSet::new()
    }
}

impl IAnalyzer for JavaAnalyzer {
    fn get_top_level_declarations(&self, file: &ProjectFile) -> Vec<CodeUnit> {
        self.inner.get_top_level_declarations(file)
    }

    fn get_analyzed_files(&self) -> BTreeSet<ProjectFile> {
        self.inner.get_analyzed_files()
    }

    fn languages(&self) -> BTreeSet<Language> {
        self.inner.languages()
    }

    fn update(&self, _changed_files: &BTreeSet<ProjectFile>) -> Self {
        self.clone()
    }

    fn update_all(&self) -> Self {
        self.clone()
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

    fn enclosing_code_unit(
        &self,
        file: &ProjectFile,
        range: &crate::analyzer::Range,
    ) -> Option<CodeUnit> {
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

    fn ranges_of(&self, code_unit: &CodeUnit) -> Vec<crate::analyzer::Range> {
        self.inner.ranges_of(code_unit)
    }

    fn get_skeleton(&self, code_unit: &CodeUnit) -> Option<String> {
        self.inner.get_skeleton(code_unit)
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
}
