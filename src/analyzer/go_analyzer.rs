use crate::analyzer::{
    AnalyzerConfig, CodeUnit, CodeUnitType, IAnalyzer, ImportAnalysisProvider, ImportInfo,
    Language, LanguageAdapter, Project, ProjectFile, TestDetectionProvider, TreeSitterAnalyzer,
    TypeAliasProvider,
};
use moka::sync::Cache;
use regex::Regex;
use std::collections::BTreeSet;
use std::mem::size_of;
use std::path::Path;
use std::sync::Arc;
use tree_sitter::{Language as TsLanguage, Node, Tree};

use super::javascript_analyzer::build_weighted_cache;

#[derive(Debug, Clone, Default)]
pub struct GoAdapter;

impl LanguageAdapter for GoAdapter {
    fn language(&self) -> Language {
        Language::Go
    }

    fn query_directory(&self) -> &'static str {
        "resources/treesitter/go"
    }

    fn parser_language(&self) -> TsLanguage {
        tree_sitter_go::LANGUAGE.into()
    }

    fn file_extension(&self) -> &'static str {
        "go"
    }

    fn contains_tests(
        &self,
        _file: &ProjectFile,
        source: &str,
        tree: &Tree,
        _parsed: &crate::analyzer::tree_sitter_analyzer::ParsedFile,
    ) -> bool {
        go_contains_tests(tree.root_node(), source)
    }

    fn extract_call_receiver(&self, reference: &str) -> Option<String> {
        let trimmed = reference.trim();
        let before_args = trimmed
            .split_once('(')
            .map(|(head, _)| head)
            .unwrap_or(trimmed);
        before_args
            .rsplit_once('.')
            .map(|(receiver, _)| receiver.to_string())
    }

    fn parse_file(
        &self,
        file: &ProjectFile,
        source: &str,
        tree: &Tree,
    ) -> crate::analyzer::tree_sitter_analyzer::ParsedFile {
        let package_name = determine_go_package_name(tree.root_node(), source);
        let mut parsed = crate::analyzer::tree_sitter_analyzer::ParsedFile::new(package_name);
        let root = tree.root_node();

        collect_go_type_identifiers(root, source, &mut parsed.type_identifiers);

        for index in 0..root.named_child_count() {
            let Some(child) = root.named_child(index) else {
                continue;
            };
            let package_name = parsed.package_name.clone();
            match child.kind() {
                "import_declaration" => visit_go_imports(child, source, &mut parsed),
                "function_declaration" => {
                    visit_go_function(file, source, child, None, package_name, &mut parsed);
                }
                "method_declaration" => {
                    visit_go_method(file, source, child, &package_name, &mut parsed)
                }
                "type_declaration" => {
                    visit_go_type_declaration(file, source, child, &package_name, &mut parsed)
                }
                "var_declaration" => visit_go_value_declaration(
                    file,
                    source,
                    child,
                    &package_name,
                    "var",
                    &mut parsed,
                ),
                "const_declaration" => visit_go_value_declaration(
                    file,
                    source,
                    child,
                    &package_name,
                    "const",
                    &mut parsed,
                ),
                _ => {}
            }
        }

        parsed
    }
}

#[derive(Clone)]
pub struct GoAnalyzer {
    inner: TreeSitterAnalyzer<GoAdapter>,
    memo_budget: u64,
    imported_code_units: Cache<ProjectFile, Arc<BTreeSet<CodeUnit>>>,
    referencing_files: Cache<ProjectFile, Arc<BTreeSet<ProjectFile>>>,
}

impl GoAnalyzer {
    pub fn new(project: Arc<dyn Project>) -> Self {
        Self::new_with_config(project, AnalyzerConfig::default())
    }

    pub fn new_with_config(project: Arc<dyn Project>, config: AnalyzerConfig) -> Self {
        let memo_budget = config.memo_cache_budget_bytes();
        Self {
            inner: TreeSitterAnalyzer::new_with_config(project, GoAdapter, config),
            memo_budget,
            imported_code_units: build_weighted_cache(memo_budget / 4, weight_code_unit_set),
            referencing_files: build_weighted_cache(memo_budget / 8, weight_project_file_set),
        }
    }

    pub fn from_project<P>(project: P) -> Self
    where
        P: Project + 'static,
    {
        Self::new(Arc::new(project))
    }

    pub fn determine_package_name(&self, source: &str) -> String {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_go::LANGUAGE.into())
            .expect("failed to load go parser");
        let Some(tree) = parser.parse(source, None) else {
            return String::new();
        };
        determine_go_package_name(tree.root_node(), source)
    }

    pub fn format_test_module(path: impl AsRef<Path>) -> String {
        let path = path.as_ref();
        let normalized = path
            .to_string_lossy()
            .replace('\\', "/")
            .trim()
            .trim_start_matches('/')
            .trim_end_matches('/')
            .trim_matches('.')
            .trim_matches('/')
            .to_string();
        if normalized.is_empty() {
            ".".to_string()
        } else {
            format!("./{normalized}")
        }
    }

    pub fn get_test_modules_static(files: &[ProjectFile]) -> Vec<String> {
        let mut modules: Vec<_> = files
            .iter()
            .map(|file| {
                Self::format_test_module(file.rel_path().parent().unwrap_or_else(|| Path::new(".")))
            })
            .collect();
        modules.sort();
        modules.dedup();
        modules
    }
}

impl ImportAnalysisProvider for GoAnalyzer {
    fn imported_code_units_of(&self, file: &ProjectFile) -> BTreeSet<CodeUnit> {
        if let Some(cached) = self.imported_code_units.get(file) {
            return (*cached).clone();
        }

        let mut resolved = BTreeSet::new();
        let all_files = self.inner.all_files();
        for import in self.inner.import_info_of(file) {
            if import.alias.as_deref() == Some("_") {
                continue;
            }
            let Some(path) = extract_go_import_path(&import.raw_snippet) else {
                continue;
            };
            let package_segment = go_import_package_segment(&path);
            let matching_files: Vec<_> = all_files
                .iter()
                .filter(|candidate| candidate != &file)
                .filter(|candidate| {
                    let parent = candidate.parent().to_string_lossy().replace('\\', "/");
                    parent == path
                        || parent.ends_with(&format!("/{path}"))
                        || self.file_package_name(candidate) == package_segment
                })
                .cloned()
                .collect();
            for target_file in matching_files {
                resolved.extend(
                    self.inner
                        .get_top_level_declarations(&target_file)
                        .into_iter()
                        .filter(|code_unit| !code_unit.is_module()),
                );
            }
        }

        self.imported_code_units
            .insert(file.clone(), Arc::new(resolved.clone()));
        resolved
    }

    fn referencing_files_of(&self, file: &ProjectFile) -> BTreeSet<ProjectFile> {
        if let Some(cached) = self.referencing_files.get(file) {
            return (*cached).clone();
        }

        let referencing: BTreeSet<_> = self
            .inner
            .all_files()
            .into_iter()
            .filter(|candidate| candidate != file)
            .filter(|candidate| {
                self.imported_code_units_of(candidate)
                    .into_iter()
                    .any(|code_unit| code_unit.source() == file)
            })
            .collect();
        self.referencing_files
            .insert(file.clone(), Arc::new(referencing.clone()));
        referencing
    }

    fn import_info_of(&self, file: &ProjectFile) -> Vec<ImportInfo> {
        self.inner.import_info_of(file)
    }

    fn relevant_imports_for(&self, code_unit: &CodeUnit) -> BTreeSet<String> {
        let source = self.inner.get_source(code_unit, false).unwrap_or_default();
        let mut relevant = BTreeSet::new();
        for import in self.inner.import_info_of(code_unit.source()) {
            if import.alias.as_deref() == Some("_") {
                continue;
            }

            let token = import
                .alias
                .as_ref()
                .filter(|alias| alias.as_str() != ".")
                .cloned()
                .or_else(|| import.identifier.clone())
                .unwrap_or_default();
            if token.is_empty() || source.contains(&token) || import.alias.as_deref() == Some(".") {
                relevant.insert(import.raw_snippet.clone());
            }
        }
        relevant
    }

    fn could_import_file(
        &self,
        source_file: &ProjectFile,
        imports: &[ImportInfo],
        target: &ProjectFile,
    ) -> bool {
        let target_parent = target.parent().to_string_lossy().replace('\\', "/");
        let target_package = self.file_package_name(target);
        imports.iter().any(|import| {
            let Some(path) = extract_go_import_path(&import.raw_snippet) else {
                return false;
            };
            let package_segment = go_import_package_segment(&path);
            target_parent == path
                || target_parent.ends_with(&format!("/{path}"))
                || target_package == package_segment
        }) || self
            .imported_code_units_of(source_file)
            .into_iter()
            .any(|code_unit| code_unit.source() == target)
    }
}

impl TypeAliasProvider for GoAnalyzer {
    fn is_type_alias(&self, code_unit: &CodeUnit) -> bool {
        self.inner.is_type_alias(code_unit)
    }
}

impl TestDetectionProvider for GoAnalyzer {}

impl IAnalyzer for GoAnalyzer {
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
            memo_budget: self.memo_budget,
            imported_code_units: build_weighted_cache(self.memo_budget / 4, weight_code_unit_set),
            referencing_files: build_weighted_cache(self.memo_budget / 8, weight_project_file_set),
        }
    }

    fn update_all(&self) -> Self {
        Self {
            inner: self.inner.update_all(),
            memo_budget: self.memo_budget,
            imported_code_units: build_weighted_cache(self.memo_budget / 4, weight_code_unit_set),
            referencing_files: build_weighted_cache(self.memo_budget / 8, weight_project_file_set),
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
        let skeleton = self.inner.get_skeleton(code_unit)?;
        if code_unit.is_class() && !skeleton.trim_start().starts_with("type ") {
            Some(format!("type {skeleton}"))
        } else {
            Some(skeleton)
        }
    }

    fn get_skeleton_header(&self, code_unit: &CodeUnit) -> Option<String> {
        let skeleton = self.inner.get_skeleton_header(code_unit)?;
        if code_unit.is_class() && !skeleton.trim_start().starts_with("type ") {
            Some(format!("type {skeleton}"))
        } else {
            Some(skeleton)
        }
    }

    fn get_source(&self, code_unit: &CodeUnit, include_comments: bool) -> Option<String> {
        let source = self.inner.get_source(code_unit, include_comments)?;
        if code_unit.is_class() && !source.trim_start().starts_with("type ") {
            Some(format!("type {source}"))
        } else {
            Some(source)
        }
    }

    fn get_sources(&self, code_unit: &CodeUnit, include_comments: bool) -> BTreeSet<String> {
        self.inner.get_sources(code_unit, include_comments)
    }

    fn search_definitions(&self, pattern: &str, auto_quote: bool) -> BTreeSet<CodeUnit> {
        self.inner.search_definitions(pattern, auto_quote)
    }

    fn signatures_of(&self, code_unit: &CodeUnit) -> Vec<String> {
        self.inner.signatures_of(code_unit)
    }

    fn import_analysis_provider(&self) -> Option<&dyn ImportAnalysisProvider> {
        Some(self)
    }

    fn type_alias_provider(&self) -> Option<&dyn TypeAliasProvider> {
        Some(self)
    }

    fn test_detection_provider(&self) -> Option<&dyn TestDetectionProvider> {
        Some(self)
    }

    fn contains_tests(&self, file: &ProjectFile) -> bool {
        self.inner.contains_tests(file)
    }

    fn get_test_modules(&self, files: &[ProjectFile]) -> Vec<String> {
        Self::get_test_modules_static(files)
    }
}

impl GoAnalyzer {
    fn file_package_name(&self, file: &ProjectFile) -> String {
        self.inner
            .get_top_level_declarations(file)
            .into_iter()
            .next()
            .map(|code_unit| code_unit.package_name().to_string())
            .unwrap_or_default()
    }
}

fn go_node_text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    source.get(node.start_byte()..node.end_byte()).unwrap_or("")
}

fn determine_go_package_name(root: Node<'_>, source: &str) -> String {
    let mut cursor = root.walk();
    for child in root.named_children(&mut cursor) {
        if child.kind() != "package_clause" {
            continue;
        }
        let mut package_cursor = child.walk();
        for package_child in child.named_children(&mut package_cursor) {
            if package_child.kind() == "package_identifier" || package_child.kind() == "identifier"
            {
                return go_node_text(package_child, source).trim().to_string();
            }
        }
    }
    String::new()
}

fn visit_go_imports(
    node: Node<'_>,
    source: &str,
    parsed: &mut crate::analyzer::tree_sitter_analyzer::ParsedFile,
) {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.kind() == "import_spec" {
            if let Some(info) = parse_go_import_spec(child, source) {
                parsed.import_statements.push(info.raw_snippet.clone());
                parsed.imports.push(info);
            }
            continue;
        }

        let mut nested_cursor = child.walk();
        for spec in child.named_children(&mut nested_cursor) {
            if spec.kind() == "import_spec"
                && let Some(info) = parse_go_import_spec(spec, source)
            {
                parsed.import_statements.push(info.raw_snippet.clone());
                parsed.imports.push(info);
            }
        }
    }
}

fn parse_go_import_spec(node: Node<'_>, source: &str) -> Option<ImportInfo> {
    let path_node = node.child_by_field_name("path").or_else(|| {
        let mut cursor = node.walk();
        node.named_children(&mut cursor)
            .find(|child| child.kind().contains("string"))
    })?;
    let raw_path = go_node_text(path_node, source).trim();
    let path = raw_path
        .trim_matches('"')
        .trim_matches('`')
        .trim_matches('\'')
        .to_string();
    if path.is_empty() {
        return None;
    }

    let alias = node
        .child_by_field_name("name")
        .map(|alias| go_node_text(alias, source).trim().to_string());
    let raw_snippet = match alias.as_deref() {
        Some(alias) => format!("import {alias} \"{path}\""),
        None => format!("import \"{path}\""),
    };
    let identifier = Some(
        alias
            .clone()
            .unwrap_or_else(|| path.rsplit('/').next().unwrap_or(path.as_str()).to_string()),
    );

    Some(ImportInfo {
        raw_snippet,
        is_wildcard: false,
        identifier,
        alias,
    })
}

fn visit_go_function(
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    parent: Option<&CodeUnit>,
    package_name: String,
    parsed: &mut crate::analyzer::tree_sitter_analyzer::ParsedFile,
) -> Option<CodeUnit> {
    let name_node = node.child_by_field_name("name")?;
    let name = go_node_text(name_node, source).trim();
    if name.is_empty() {
        return None;
    }
    let short_name = parent
        .map(|parent| format!("{}.{}", parent.short_name(), name))
        .unwrap_or_else(|| name.to_string());
    let signature = node
        .child_by_field_name("parameters")
        .map(|parameters| go_node_text(parameters, source).trim().to_string());
    let code_unit = CodeUnit::with_signature(
        file.clone(),
        CodeUnitType::Function,
        package_name,
        short_name,
        signature,
        false,
    );
    let top_level = parent.cloned().unwrap_or_else(|| code_unit.clone());
    parsed.add_code_unit(
        code_unit.clone(),
        node,
        source,
        parent.cloned(),
        Some(top_level),
    );
    parsed.add_signature(code_unit.clone(), go_function_signature(node, source));
    Some(code_unit)
}

fn visit_go_method(
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    package_name: &str,
    parsed: &mut crate::analyzer::tree_sitter_analyzer::ParsedFile,
) {
    let Some(receiver) = node.child_by_field_name("receiver") else {
        return;
    };
    let Some(receiver_name) = extract_go_receiver_name(receiver, source) else {
        return;
    };
    let parent = CodeUnit::new(
        file.clone(),
        CodeUnitType::Class,
        package_name.to_string(),
        receiver_name,
    );
    let _ = visit_go_function(
        file,
        source,
        node,
        Some(&parent),
        package_name.to_string(),
        parsed,
    );
}

fn visit_go_type_declaration(
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    package_name: &str,
    parsed: &mut crate::analyzer::tree_sitter_analyzer::ParsedFile,
) {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        match child.kind() {
            "type_spec" => {
                let _ = visit_go_type_spec(file, source, child, package_name, parsed);
            }
            "type_alias" => {
                let _ = visit_go_type_alias(file, source, child, package_name, parsed);
            }
            _ => {
                let mut nested_cursor = child.walk();
                for spec in child.named_children(&mut nested_cursor) {
                    match spec.kind() {
                        "type_spec" => {
                            let _ = visit_go_type_spec(file, source, spec, package_name, parsed);
                        }
                        "type_alias" => {
                            let _ = visit_go_type_alias(file, source, spec, package_name, parsed);
                        }
                        _ => {}
                    }
                }
            }
        }
    }
}

fn visit_go_type_spec(
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    package_name: &str,
    parsed: &mut crate::analyzer::tree_sitter_analyzer::ParsedFile,
) -> Option<CodeUnit> {
    let name_node = node.child_by_field_name("name")?;
    let type_node = node.child_by_field_name("type")?;
    let name = go_node_text(name_node, source).trim();
    if name.is_empty() {
        return None;
    }

    let code_unit = CodeUnit::new(
        file.clone(),
        CodeUnitType::Class,
        package_name.to_string(),
        name.to_string(),
    );
    parsed.add_code_unit(
        code_unit.clone(),
        node,
        source,
        None,
        Some(code_unit.clone()),
    );
    parsed.add_signature(code_unit.clone(), go_type_signature(node, source));

    match type_node.kind() {
        "struct_type" => {
            visit_go_struct_fields(file, source, type_node, &code_unit, package_name, parsed)
        }
        "interface_type" => {
            visit_go_interface_methods(file, source, type_node, &code_unit, package_name, parsed);
        }
        _ => {}
    }
    Some(code_unit)
}

fn visit_go_type_alias(
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    package_name: &str,
    parsed: &mut crate::analyzer::tree_sitter_analyzer::ParsedFile,
) -> Option<CodeUnit> {
    let name_node = node.child_by_field_name("name")?;
    let name = go_node_text(name_node, source).trim();
    if name.is_empty() {
        return None;
    }

    let code_unit = CodeUnit::new(
        file.clone(),
        CodeUnitType::Field,
        package_name.to_string(),
        format!("_module_.{name}"),
    );
    parsed.add_code_unit(
        code_unit.clone(),
        node,
        source,
        None,
        Some(code_unit.clone()),
    );
    parsed.add_signature(
        code_unit.clone(),
        go_node_text(node, source).trim().to_string(),
    );
    parsed.mark_type_alias(code_unit);
    Some(CodeUnit::new(
        file.clone(),
        CodeUnitType::Field,
        package_name.to_string(),
        format!("_module_.{name}"),
    ))
}

fn visit_go_struct_fields(
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    parent: &CodeUnit,
    package_name: &str,
    parsed: &mut crate::analyzer::tree_sitter_analyzer::ParsedFile,
) {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.kind() != "field_declaration_list" {
            continue;
        }
        let mut field_cursor = child.walk();
        for field in child.named_children(&mut field_cursor) {
            if field.kind() != "field_declaration" {
                continue;
            }
            let suffix = go_struct_field_suffix(field, source);
            let mut name_cursor = field.walk();
            for name in field.named_children(&mut name_cursor) {
                if name.kind() != "field_identifier" {
                    continue;
                }
                let field_name = go_node_text(name, source).trim();
                if field_name.is_empty() {
                    continue;
                }
                let code_unit = CodeUnit::new(
                    file.clone(),
                    CodeUnitType::Field,
                    package_name.to_string(),
                    format!("{}.{}", parent.short_name(), field_name),
                );
                parsed.add_code_unit(
                    code_unit.clone(),
                    name,
                    source,
                    Some(parent.clone()),
                    Some(parent.clone()),
                );
                parsed.add_signature(code_unit, format!("{field_name}{suffix}"));
            }
        }
    }
}

fn visit_go_interface_methods(
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    parent: &CodeUnit,
    package_name: &str,
    parsed: &mut crate::analyzer::tree_sitter_analyzer::ParsedFile,
) {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.kind() != "method_elem" {
            continue;
        }
        let Some(name_node) = child.child_by_field_name("name") else {
            continue;
        };
        let name = go_node_text(name_node, source).trim();
        if name.is_empty() {
            continue;
        }
        let signature = child
            .child_by_field_name("parameters")
            .map(|parameters| go_node_text(parameters, source).trim().to_string());
        let code_unit = CodeUnit::with_signature(
            file.clone(),
            CodeUnitType::Function,
            package_name.to_string(),
            format!("{}.{}", parent.short_name(), name),
            signature,
            false,
        );
        parsed.add_code_unit(
            code_unit.clone(),
            child,
            source,
            Some(parent.clone()),
            Some(parent.clone()),
        );
        parsed.add_signature(code_unit, go_node_text(child, source).trim().to_string());
    }
}

fn visit_go_value_declaration(
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    package_name: &str,
    keyword: &str,
    parsed: &mut crate::analyzer::tree_sitter_analyzer::ParsedFile,
) {
    let spec_kind = if keyword == "const" {
        "const_spec"
    } else {
        "var_spec"
    };
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.kind() == spec_kind {
            visit_go_value_spec(file, source, child, package_name, keyword, parsed);
            continue;
        }
        let mut nested_cursor = child.walk();
        for spec in child.named_children(&mut nested_cursor) {
            if spec.kind() == spec_kind {
                visit_go_value_spec(file, source, spec, package_name, keyword, parsed);
            }
        }
    }
}

fn visit_go_value_spec(
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    package_name: &str,
    keyword: &str,
    parsed: &mut crate::analyzer::tree_sitter_analyzer::ParsedFile,
) {
    let identifier_count = {
        let mut cursor = node.walk();
        node.named_children(&mut cursor)
            .filter(|child| child.kind() == "identifier")
            .count()
    };
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.kind() != "identifier" {
            continue;
        }
        let name = go_node_text(child, source).trim();
        if name.is_empty() {
            continue;
        }
        let code_unit = CodeUnit::new(
            file.clone(),
            CodeUnitType::Field,
            package_name.to_string(),
            format!("_module_.{name}"),
        );
        parsed.add_code_unit(
            code_unit.clone(),
            child,
            source,
            None,
            Some(code_unit.clone()),
        );
        parsed.add_signature(
            code_unit,
            go_value_signature(node, source, keyword, name, identifier_count),
        );
    }
}

fn go_type_signature(node: Node<'_>, source: &str) -> String {
    let raw = go_node_text(node, source).trim();
    if raw.contains('{') {
        format!("{} {{", raw.split('{').next().unwrap_or(raw).trim())
    } else {
        raw.to_string()
    }
}

fn go_function_signature(node: Node<'_>, source: &str) -> String {
    let raw = go_node_text(node, source).trim();
    let header = raw.split('{').next().unwrap_or(raw).trim();
    if node.kind() == "method_declaration" || node.kind() == "function_declaration" {
        format!("{header} {{ ... }}")
    } else {
        header.to_string()
    }
}

fn go_value_signature(
    node: Node<'_>,
    source: &str,
    keyword: &str,
    name: &str,
    identifier_count: usize,
) -> String {
    let raw = go_node_text(node, source).trim();
    let after_keyword = raw.strip_prefix(keyword).map(str::trim).unwrap_or(raw);
    if identifier_count > 1 && after_keyword.contains('=') {
        return name.to_string();
    }

    let remainder = after_keyword
        .strip_prefix(name)
        .map(str::trim)
        .unwrap_or(after_keyword);
    let (type_part, value_part) = remainder
        .split_once('=')
        .map(|(left, right)| (left.trim(), Some(right.trim())))
        .unwrap_or((remainder.trim(), None));

    let mut signature = name.to_string();
    if !type_part.is_empty() {
        signature.push(' ');
        signature.push_str(type_part);
    }

    if let Some(value) = value_part
        && go_value_is_simple_literal(value)
    {
        signature.push_str(" = ");
        signature.push_str(value);
    }

    signature
}

fn extract_go_receiver_name(node: Node<'_>, source: &str) -> Option<String> {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        match child.kind() {
            "parameter_declaration" => {
                let type_node = child.child_by_field_name("type").unwrap_or(child);
                if let Some(name) = extract_go_type_name(type_node, source) {
                    return Some(name);
                }
            }
            _ => {
                if let Some(name) = extract_go_type_name(child, source) {
                    return Some(name);
                }
            }
        }
    }
    None
}

fn extract_go_type_name(node: Node<'_>, source: &str) -> Option<String> {
    match node.kind() {
        "type_identifier" | "identifier" => {
            let text = go_node_text(node, source).trim();
            (!text.is_empty()).then(|| text.to_string())
        }
        "pointer_type" | "slice_type" | "array_type" | "generic_type" => {
            let mut cursor = node.walk();
            node.named_children(&mut cursor)
                .find_map(|child| extract_go_type_name(child, source))
        }
        "qualified_type" => node
            .child_by_field_name("name")
            .or_else(|| {
                let mut cursor = node.walk();
                node.named_children(&mut cursor).last()
            })
            .and_then(|child| extract_go_type_name(child, source)),
        _ => {
            let mut cursor = node.walk();
            node.named_children(&mut cursor)
                .find_map(|child| extract_go_type_name(child, source))
        }
    }
}

fn collect_go_type_identifiers(node: Node<'_>, source: &str, identifiers: &mut BTreeSet<String>) {
    match node.kind() {
        "identifier" | "type_identifier" | "field_identifier" | "package_identifier" => {
            let text = go_node_text(node, source).trim();
            if !text.is_empty() {
                identifiers.insert(text.to_string());
            }
        }
        _ => {}
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        collect_go_type_identifiers(child, source, identifiers);
    }
}

fn go_contains_tests(root: Node<'_>, source: &str) -> bool {
    let mut cursor = root.walk();
    for child in root.named_children(&mut cursor) {
        if child.kind() != "function_declaration" {
            continue;
        }
        if is_go_test_function(child, source) {
            return true;
        }
    }
    false
}

fn is_go_test_function(node: Node<'_>, source: &str) -> bool {
    let Some(name_node) = node.child_by_field_name("name") else {
        return false;
    };
    let name = go_node_text(name_node, source).trim();
    if !name.starts_with("Test") || node.child_by_field_name("type_parameters").is_some() {
        return false;
    }
    let Some(parameters) = node.child_by_field_name("parameters") else {
        return false;
    };
    let raw = go_node_text(parameters, source).replace(char::is_whitespace, "");
    static GO_TEST_PARAM_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
        Regex::new(r"^\([A-Za-z_][A-Za-z0-9_]*(\*?)testing\.T\)$").unwrap()
    });
    GO_TEST_PARAM_RE.is_match(&raw)
}

fn extract_go_import_path(raw_import: &str) -> Option<String> {
    let trimmed = raw_import.trim();
    trimmed
        .split_whitespace()
        .next_back()
        .map(|path| {
            path.trim_matches('"')
                .trim_matches('`')
                .trim_matches('\'')
                .to_string()
        })
        .filter(|path| !path.is_empty())
}

fn go_import_package_segment(path: &str) -> String {
    let segment = path.rsplit('/').next().unwrap_or(path);
    segment
        .split_once(".v")
        .map(|(base, _)| base)
        .unwrap_or(segment)
        .to_string()
}

fn go_struct_field_suffix(node: Node<'_>, source: &str) -> String {
    let mut cursor = node.walk();
    let mut type_start = None;
    for child in node.named_children(&mut cursor) {
        if child.kind() == "field_identifier" {
            continue;
        }
        type_start = Some(child.start_byte());
        break;
    }
    type_start
        .and_then(|start| source.get(start..node.end_byte()))
        .map(|suffix| format!(" {}", suffix.trim()))
        .unwrap_or_default()
}

fn go_value_is_simple_literal(value: &str) -> bool {
    let trimmed = value.trim();
    trimmed == "iota"
        || trimmed == "true"
        || trimmed == "false"
        || trimmed == "nil"
        || trimmed.parse::<i128>().is_ok()
        || trimmed.parse::<f64>().is_ok()
        || (trimmed.starts_with('"') && trimmed.ends_with('"'))
        || (trimmed.starts_with('`') && trimmed.ends_with('`'))
        || (trimmed.starts_with('\'') && trimmed.ends_with('\''))
}

fn weight_project_file_set(_key: &ProjectFile, value: &Arc<BTreeSet<ProjectFile>>) -> u32 {
    let size = value
        .iter()
        .map(|item| item.rel_path().to_string_lossy().len() + size_of::<ProjectFile>())
        .sum::<usize>()
        + size_of::<BTreeSet<ProjectFile>>();
    size.min(u32::MAX as usize) as u32
}

fn weight_code_unit_set(_key: &ProjectFile, value: &Arc<BTreeSet<CodeUnit>>) -> u32 {
    let size = value
        .iter()
        .map(|item| item.fq_name().len() + size_of::<CodeUnit>())
        .sum::<usize>()
        + size_of::<BTreeSet<CodeUnit>>();
    size.min(u32::MAX as usize) as u32
}
