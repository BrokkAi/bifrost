use crate::analyzer::{
    AnalyzerConfig, CodeUnit, IAnalyzer, ImportAnalysisProvider, ImportInfo, Language,
    LanguageAdapter, Project, ProjectFile, TestDetectionProvider, TreeSitterAnalyzer,
};
use moka::sync::Cache;
use std::collections::BTreeSet;
use std::mem::size_of;
use std::path::Path;
use std::sync::Arc;
use tree_sitter::{Language as TsLanguage, Node, Parser, Tree};

#[derive(Debug, Clone, Default)]
pub struct JavascriptAdapter;

impl LanguageAdapter for JavascriptAdapter {
    fn language(&self) -> Language {
        Language::JavaScript
    }

    fn query_directory(&self) -> &'static str {
        "resources/treesitter/javascript"
    }

    fn parser_language(&self) -> TsLanguage {
        tree_sitter_javascript::LANGUAGE.into()
    }

    fn file_extension(&self) -> &'static str {
        "js"
    }

    fn extract_call_receiver(&self, reference: &str) -> Option<String> {
        extract_js_ts_call_receiver(reference)
    }

    fn contains_tests(
        &self,
        file: &ProjectFile,
        source: &str,
        _tree: &Tree,
        _parsed: &crate::analyzer::tree_sitter_analyzer::ParsedFile,
    ) -> bool {
        js_ts_contains_tests(file, source)
    }

    fn parse_file(
        &self,
        file: &ProjectFile,
        source: &str,
        tree: &Tree,
    ) -> crate::analyzer::tree_sitter_analyzer::ParsedFile {
        let root = tree.root_node();
        let mut parsed = crate::analyzer::tree_sitter_analyzer::ParsedFile::new(String::new());
        let module = module_code_unit(file);
        let mut module_has_imports = false;

        for index in 0..root.named_child_count() {
            let Some(child) = root.named_child(index) else {
                continue;
            };
            match child.kind() {
                "import_statement" => {
                    let raw = node_text(child, source).trim().to_string();
                    module_has_imports = true;
                    parsed.import_statements.push(raw.clone());
                    parsed.imports.extend(parse_js_import_infos(&raw));
                }
                "expression_statement" => {
                    if let Some(raw) = extract_require_statement(child, source) {
                        module_has_imports = true;
                        parsed.import_statements.push(raw.clone());
                        parsed.imports.extend(parse_js_import_infos(&raw));
                    }
                }
                "export_statement" => {
                    visit_js_export(file, source, child, &mut parsed);
                }
                "class_declaration" => {
                    visit_js_class(file, source, child, None, &mut parsed, false);
                }
                "function_declaration" => {
                    visit_js_function(file, source, child, None, &mut parsed, false);
                }
                "lexical_declaration" | "variable_declaration" => {
                    visit_js_variable_statement(file, source, child, None, &mut parsed, false);
                }
                _ => {}
            }
        }

        if module_has_imports {
            parsed.top_level_declarations.insert(0, module.clone());
            parsed.declarations.insert(module.clone());
            parsed.add_signature(module, parsed.import_statements.join("\n"));
        }

        parsed
    }
}

#[derive(Clone)]
pub struct JavascriptAnalyzer {
    inner: TreeSitterAnalyzer<JavascriptAdapter>,
    memo_budget: u64,
    memo_caches: Arc<JsMemoCaches>,
}

#[derive(Clone)]
struct JsMemoCaches {
    imported_code_units: Cache<ProjectFile, Arc<BTreeSet<CodeUnit>>>,
    referencing_files: Cache<ProjectFile, Arc<BTreeSet<ProjectFile>>>,
    relevant_imports: Cache<CodeUnit, Arc<BTreeSet<String>>>,
}

impl JsMemoCaches {
    fn new(budget_bytes: u64) -> Self {
        Self {
            imported_code_units: build_weighted_cache(budget_bytes / 3, weight_code_unit_set),
            referencing_files: build_weighted_cache(budget_bytes / 6, weight_project_file_set),
            relevant_imports: build_weighted_cache(budget_bytes / 6, weight_string_set),
        }
    }
}

impl JavascriptAnalyzer {
    pub fn new(project: Arc<dyn Project>) -> Self {
        Self::new_with_config(project, AnalyzerConfig::default())
    }

    pub fn new_with_config(project: Arc<dyn Project>, config: AnalyzerConfig) -> Self {
        let memo_budget = config.memo_cache_budget_bytes();
        Self {
            inner: TreeSitterAnalyzer::new_with_config(project, JavascriptAdapter, config),
            memo_budget,
            memo_caches: Arc::new(JsMemoCaches::new(memo_budget)),
        }
    }

    pub fn from_project<P>(project: P) -> Self
    where
        P: Project + 'static,
    {
        Self::new(Arc::new(project))
    }

    pub fn inner(&self) -> &TreeSitterAnalyzer<JavascriptAdapter> {
        &self.inner
    }

    pub fn extract_type_identifiers(&self, source: &str) -> BTreeSet<String> {
        extract_js_type_identifiers(source)
    }
}

impl ImportAnalysisProvider for JavascriptAnalyzer {
    fn imported_code_units_of(&self, file: &ProjectFile) -> BTreeSet<CodeUnit> {
        if let Some(cached) = self.memo_caches.imported_code_units.get(file) {
            return (*cached).clone();
        }

        let mut resolved = BTreeSet::new();
        for import in self.inner.import_info_of(file) {
            for target in
                resolve_js_ts_import_paths(file, &import.raw_snippet, Language::JavaScript)
            {
                let top_level = self.inner.get_top_level_declarations(&target);
                if import.is_wildcard {
                    resolved.extend(
                        top_level
                            .into_iter()
                            .filter(|code_unit| !code_unit.is_module()),
                    );
                } else if let Some(identifier) =
                    import.alias.as_ref().or(import.identifier.as_ref())
                {
                    resolved.extend(
                        top_level
                            .iter()
                            .filter(|code_unit| code_unit.identifier() == identifier)
                            .cloned(),
                    );
                    if resolved.is_empty() && top_level.len() == 1 && !top_level[0].is_module() {
                        resolved.insert(top_level[0].clone());
                    }
                } else {
                    resolved.extend(
                        top_level
                            .into_iter()
                            .filter(|code_unit| !code_unit.is_module()),
                    );
                }
            }
        }

        self.memo_caches
            .imported_code_units
            .insert(file.clone(), Arc::new(resolved.clone()));
        resolved
    }

    fn referencing_files_of(&self, file: &ProjectFile) -> BTreeSet<ProjectFile> {
        if let Some(cached) = self.memo_caches.referencing_files.get(file) {
            return (*cached).clone();
        }

        let mut referencing = BTreeSet::new();
        for candidate in self.inner.all_files() {
            if &candidate == file {
                continue;
            }
            if self
                .imported_code_units_of(&candidate)
                .into_iter()
                .any(|code_unit| code_unit.source() == file)
            {
                referencing.insert(candidate);
            }
        }

        self.memo_caches
            .referencing_files
            .insert(file.clone(), Arc::new(referencing.clone()));
        referencing
    }

    fn import_info_of(&self, file: &ProjectFile) -> Vec<ImportInfo> {
        self.inner.import_info_of(file)
    }

    fn relevant_imports_for(&self, code_unit: &CodeUnit) -> BTreeSet<String> {
        if let Some(cached) = self.memo_caches.relevant_imports.get(code_unit) {
            return (*cached).clone();
        }

        let source = self.inner.get_source(code_unit, false).unwrap_or_default();
        let mut relevant = BTreeSet::new();
        for import in self.inner.import_info_of(code_unit.source()) {
            let tokens = imported_tokens(&import.raw_snippet);
            if tokens.is_empty() || tokens.iter().any(|token| source.contains(token)) {
                relevant.insert(import.raw_snippet.clone());
            }
        }

        self.memo_caches
            .relevant_imports
            .insert(code_unit.clone(), Arc::new(relevant.clone()));
        relevant
    }

    fn could_import_file(
        &self,
        source_file: &ProjectFile,
        imports: &[ImportInfo],
        target: &ProjectFile,
    ) -> bool {
        imports.iter().any(|import| {
            resolve_js_ts_import_paths(source_file, &import.raw_snippet, Language::JavaScript)
                .into_iter()
                .any(|candidate| candidate == *target)
        })
    }
}

impl TestDetectionProvider for JavascriptAnalyzer {}

impl IAnalyzer for JavascriptAnalyzer {
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
            memo_caches: Arc::new(JsMemoCaches::new(self.memo_budget)),
        }
    }

    fn update_all(&self) -> Self {
        Self {
            inner: self.inner.update_all(),
            memo_budget: self.memo_budget,
            memo_caches: Arc::new(JsMemoCaches::new(self.memo_budget)),
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

    fn import_analysis_provider(&self) -> Option<&dyn ImportAnalysisProvider> {
        Some(self)
    }

    fn test_detection_provider(&self) -> Option<&dyn TestDetectionProvider> {
        Some(self)
    }

    fn contains_tests(&self, file: &ProjectFile) -> bool {
        self.inner.contains_tests(file)
    }
}

fn visit_js_export(
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    parsed: &mut crate::analyzer::tree_sitter_analyzer::ParsedFile,
) {
    if let Some(declaration) = node.child_by_field_name("declaration") {
        match declaration.kind() {
            "class_declaration" => {
                visit_js_class(file, source, node, None, parsed, true);
            }
            "function_declaration" => {
                visit_js_function(file, source, node, None, parsed, true);
            }
            "lexical_declaration" | "variable_declaration" => {
                visit_js_variable_statement(file, source, node, None, parsed, true);
            }
            _ => {}
        }
    }
}

fn visit_js_class(
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    parent: Option<&CodeUnit>,
    parsed: &mut crate::analyzer::tree_sitter_analyzer::ParsedFile,
    exported: bool,
) -> Option<CodeUnit> {
    let definition = if node.kind() == "export_statement" {
        node.child_by_field_name("declaration").unwrap_or(node)
    } else {
        node
    };
    let name_node = definition.child_by_field_name("name")?;
    let name = node_text(name_node, source).trim();
    if name.is_empty() {
        return None;
    }

    let short_name = parent
        .map(|parent| format!("{}.{}", parent.short_name(), name))
        .unwrap_or_else(|| name.to_string());
    let code_unit = CodeUnit::new(
        file.clone(),
        crate::analyzer::CodeUnitType::Class,
        "",
        short_name,
    );
    let top_level = parent.cloned().unwrap_or_else(|| code_unit.clone());
    parsed.add_code_unit(
        code_unit.clone(),
        definition,
        source,
        parent.cloned(),
        Some(top_level.clone()),
    );
    parsed.add_signature(
        code_unit.clone(),
        js_class_signature(node, source, exported),
    );

    if let Some(body) = definition.child_by_field_name("body") {
        for index in 0..body.named_child_count() {
            let Some(child) = body.named_child(index) else {
                continue;
            };
            match child.kind() {
                "method_definition" => {
                    visit_js_method(file, source, child, &code_unit, &top_level, parsed)
                }
                "field_definition" | "public_field_definition" => {
                    visit_js_field(file, source, child, &code_unit, &top_level, parsed);
                }
                _ => {}
            }
        }
    }

    Some(code_unit)
}

fn visit_js_function(
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    parent: Option<&CodeUnit>,
    parsed: &mut crate::analyzer::tree_sitter_analyzer::ParsedFile,
    exported: bool,
) -> Option<CodeUnit> {
    let definition = if node.kind() == "export_statement" {
        node.child_by_field_name("declaration").unwrap_or(node)
    } else {
        node
    };
    let name_node = definition.child_by_field_name("name")?;
    let name = node_text(name_node, source).trim();
    if name.is_empty() {
        return None;
    }

    let short_name = parent
        .map(|parent| format!("{}.{}", parent.short_name(), name))
        .unwrap_or_else(|| name.to_string());
    let code_unit = CodeUnit::new(
        file.clone(),
        crate::analyzer::CodeUnitType::Function,
        "",
        short_name,
    );
    let top_level = parent.cloned().unwrap_or_else(|| code_unit.clone());
    parsed.add_code_unit(
        code_unit.clone(),
        definition,
        source,
        parent.cloned(),
        Some(top_level),
    );
    parsed.add_signature(
        code_unit.clone(),
        js_function_signature(definition, source, name, exported),
    );
    Some(code_unit)
}

fn visit_js_method(
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    parent: &CodeUnit,
    top_level: &CodeUnit,
    parsed: &mut crate::analyzer::tree_sitter_analyzer::ParsedFile,
) {
    let Some(name_node) = node.child_by_field_name("name") else {
        return;
    };
    let name = node_text(name_node, source).trim_matches('"').trim();
    if name.is_empty() {
        return;
    }

    let code_unit = CodeUnit::new(
        file.clone(),
        crate::analyzer::CodeUnitType::Function,
        "",
        format!("{}.{}", parent.short_name(), name),
    );
    parsed.add_code_unit(
        code_unit.clone(),
        node,
        source,
        Some(parent.clone()),
        Some(top_level.clone()),
    );
    parsed.add_signature(code_unit, js_method_signature(node, source));
}

fn visit_js_field(
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    parent: &CodeUnit,
    top_level: &CodeUnit,
    parsed: &mut crate::analyzer::tree_sitter_analyzer::ParsedFile,
) {
    let Some(name_node) = node.child_by_field_name("name") else {
        return;
    };
    let name = node_text(name_node, source).trim_matches('"').trim();
    if name.is_empty() {
        return;
    }
    let code_unit = CodeUnit::new(
        file.clone(),
        crate::analyzer::CodeUnitType::Field,
        "",
        format!("{}.{}", parent.short_name(), name),
    );
    parsed.add_code_unit(
        code_unit.clone(),
        node,
        source,
        Some(parent.clone()),
        Some(top_level.clone()),
    );
    parsed.add_signature(code_unit, trim_statement(node_text(node, source)));
}

fn visit_js_variable_statement(
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    parent: Option<&CodeUnit>,
    parsed: &mut crate::analyzer::tree_sitter_analyzer::ParsedFile,
    exported: bool,
) {
    let definition = if node.kind() == "export_statement" {
        node.child_by_field_name("declaration").unwrap_or(node)
    } else {
        node
    };
    for index in 0..definition.named_child_count() {
        let Some(child) = definition.named_child(index) else {
            continue;
        };
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

        let value = child.child_by_field_name("value");
        let is_function = value
            .map(|value| matches!(value.kind(), "arrow_function" | "function_expression"))
            .unwrap_or(false);
        let kind = if is_function {
            crate::analyzer::CodeUnitType::Function
        } else {
            crate::analyzer::CodeUnitType::Field
        };
        let short_name = if kind == crate::analyzer::CodeUnitType::Field {
            parent
                .map(|parent| format!("{}.{}", parent.short_name(), name))
                .unwrap_or_else(|| {
                    format!(
                        "{}.{}",
                        file.rel_path()
                            .file_name()
                            .and_then(|name| name.to_str())
                            .unwrap_or("module"),
                        name
                    )
                })
        } else {
            parent
                .map(|parent| format!("{}.{}", parent.short_name(), name))
                .unwrap_or_else(|| name.to_string())
        };
        let code_unit = CodeUnit::new(file.clone(), kind, "", short_name);
        let top_level = parent.cloned().unwrap_or_else(|| code_unit.clone());
        parsed.add_code_unit(
            code_unit.clone(),
            definition,
            source,
            parent.cloned(),
            Some(top_level),
        );
        if is_function {
            parsed.add_signature(
                code_unit,
                js_variable_function_signature(definition, child, source, name, exported),
            );
        } else {
            parsed.add_signature(
                code_unit,
                js_variable_signature(definition, child, source, exported),
            );
        }
    }
}

pub(crate) fn node_text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    source.get(node.start_byte()..node.end_byte()).unwrap_or("")
}

pub(crate) fn module_code_unit(file: &ProjectFile) -> CodeUnit {
    CodeUnit::new(
        file.clone(),
        crate::analyzer::CodeUnitType::Module,
        "",
        file.rel_path()
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("module"),
    )
}

pub(crate) fn trim_statement(text: &str) -> String {
    text.trim().trim_end_matches(';').trim().to_string()
}

fn one_line(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn js_class_signature(node: Node<'_>, source: &str, exported: bool) -> String {
    let definition = if node.kind() == "export_statement" {
        node.child_by_field_name("declaration").unwrap_or(node)
    } else {
        node
    };
    let mut signature = node_text(definition, source)
        .split('{')
        .next()
        .unwrap_or("")
        .trim()
        .to_string();
    if exported && !signature.starts_with("export ") {
        signature = format!("export {signature}");
    }
    format!("{} {{", one_line(&signature))
}

fn js_function_signature(node: Node<'_>, source: &str, name: &str, exported: bool) -> String {
    let mut prefix = if exported { "export " } else { "" }.to_string();
    let async_prefix = if node
        .child_by_field_name("body")
        .map(|_| node_text(node, source).contains("async "))
        .unwrap_or(false)
    {
        "async "
    } else {
        ""
    };
    let params = node
        .child_by_field_name("parameters")
        .map(|parameters| node_text(parameters, source).trim().to_string())
        .unwrap_or_else(|| "()".to_string());
    prefix.push_str(async_prefix);
    let jsx_suffix = if exported && is_component_like_name(name) && node_returns_jsx(node, source) {
        ": JSX.Element"
    } else {
        ""
    };
    format!("{prefix}function {name}{params}{jsx_suffix} ...")
}

fn js_method_signature(node: Node<'_>, source: &str) -> String {
    let name = node
        .child_by_field_name("name")
        .map(|name| node_text(name, source).trim_matches('"').trim().to_string())
        .unwrap_or_else(|| "method".to_string());
    let params = node
        .child_by_field_name("parameters")
        .map(|parameters| node_text(parameters, source).trim().to_string())
        .unwrap_or_else(|| "()".to_string());
    let jsx_suffix = if name == "render" && node_returns_jsx(node, source) {
        ": JSX.Element"
    } else {
        ""
    };
    format!("function {name}{params}{jsx_suffix} ...")
}

fn js_variable_function_signature(
    _statement: Node<'_>,
    declarator: Node<'_>,
    source: &str,
    name: &str,
    exported: bool,
) -> String {
    let value = declarator
        .child_by_field_name("value")
        .unwrap_or(declarator);
    let async_prefix = if node_text(value, source).trim_start().starts_with("async ") {
        "async "
    } else {
        ""
    };
    let params = value
        .child_by_field_name("parameters")
        .map(|parameters| node_text(parameters, source).trim().to_string())
        .unwrap_or_else(|| "()".to_string());
    let jsx_suffix = if exported && is_component_like_name(name) && node_returns_jsx(value, source)
    {
        ": JSX.Element"
    } else {
        ""
    };
    let export_prefix = if exported { "export " } else { "" };
    format!("{export_prefix}{async_prefix}{name}{params}{jsx_suffix} => ...")
}

fn js_variable_signature(
    statement: Node<'_>,
    declarator: Node<'_>,
    source: &str,
    exported: bool,
) -> String {
    let header = js_variable_header(statement, declarator, source, exported);
    match declarator.child_by_field_name("value") {
        Some(value) if is_simple_js_initializer(value) => {
            let value_text = trim_statement(node_text(value, source));
            format!("{header} = {value_text}")
        }
        _ => header,
    }
}

fn js_variable_header(
    statement: Node<'_>,
    declarator: Node<'_>,
    source: &str,
    exported: bool,
) -> String {
    let keyword = statement
        .child(0)
        .map(|node| node_text(node, source).trim().to_string())
        .unwrap_or_else(|| "const".to_string());
    let declarator_text = trim_statement(node_text(declarator, source));
    let left = declarator_text
        .split('=')
        .next()
        .map(trim_statement)
        .unwrap_or(declarator_text);
    let export_prefix = if exported { "export " } else { "" };
    format!("{export_prefix}{keyword} {left}")
}

fn is_simple_js_initializer(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "string"
            | "number"
            | "true"
            | "false"
            | "null"
            | "undefined"
            | "template_string"
            | "unary_expression"
            | "binary_expression"
            | "identifier"
            | "member_expression"
            | "new_expression"
    )
}

pub(crate) fn parse_js_import_infos(raw: &str) -> Vec<ImportInfo> {
    let trimmed = raw.trim().trim_end_matches(';').trim();
    if trimmed.starts_with("import ") {
        parse_es_import_infos(raw)
    } else if trimmed.contains("require(") {
        parse_require_import_infos(raw)
    } else {
        Vec::new()
    }
}

fn parse_es_import_infos(raw: &str) -> Vec<ImportInfo> {
    let trimmed = raw.trim().trim_end_matches(';').trim();
    if !trimmed.starts_with("import ") {
        return Vec::new();
    }
    let Some((head, _path)) = trimmed[7..].rsplit_once(" from ") else {
        return vec![ImportInfo {
            raw_snippet: raw.trim().to_string(),
            is_wildcard: false,
            identifier: None,
            alias: None,
        }];
    };
    let head = head.trim();
    if head.starts_with('*') {
        return vec![ImportInfo {
            raw_snippet: raw.trim().to_string(),
            is_wildcard: true,
            identifier: None,
            alias: head.split_whitespace().last().map(str::to_string),
        }];
    }
    let mut imports = Vec::new();
    if let Some((default_import, named)) = head.split_once(',') {
        let default_import = default_import.trim();
        if !default_import.is_empty() {
            imports.push(ImportInfo {
                raw_snippet: raw.trim().to_string(),
                is_wildcard: false,
                identifier: Some(default_import.to_string()),
                alias: None,
            });
        }
        imports.extend(parse_named_imports(raw, named));
        return imports;
    }
    if head.starts_with('{') {
        return parse_named_imports(raw, head);
    }
    vec![ImportInfo {
        raw_snippet: raw.trim().to_string(),
        is_wildcard: false,
        identifier: Some(head.to_string()),
        alias: None,
    }]
}

fn parse_named_imports(raw: &str, named: &str) -> Vec<ImportInfo> {
    named
        .trim()
        .trim_start_matches('{')
        .trim_end_matches('}')
        .split(',')
        .filter_map(|entry| {
            let entry = entry.trim();
            if entry.is_empty() {
                return None;
            }
            let (identifier, alias) = entry
                .split_once(" as ")
                .map(|(identifier, alias)| (identifier.trim(), Some(alias.trim().to_string())))
                .unwrap_or((entry, None));
            Some(ImportInfo {
                raw_snippet: raw.trim().to_string(),
                is_wildcard: false,
                identifier: Some(identifier.to_string()),
                alias,
            })
        })
        .collect()
}

fn parse_require_import_infos(raw: &str) -> Vec<ImportInfo> {
    let trimmed = raw.trim().trim_end_matches(';').trim();
    let Some((left, _)) = trimmed.split_once("require(") else {
        return Vec::new();
    };
    let left = left.trim();
    if let Some(pattern) = left
        .strip_prefix("const ")
        .or_else(|| left.strip_prefix("let "))
        .or_else(|| left.strip_prefix("var "))
    {
        let pattern = pattern.trim().trim_end_matches('=').trim();
        if pattern.starts_with('{') {
            return pattern
                .trim_start_matches('{')
                .trim_end_matches('}')
                .split(',')
                .filter_map(|entry| {
                    let entry = entry.trim();
                    if entry.is_empty() {
                        return None;
                    }
                    let (identifier, alias) = entry
                        .split_once(':')
                        .map(|(identifier, alias)| {
                            (identifier.trim(), Some(alias.trim().to_string()))
                        })
                        .unwrap_or((entry, None));
                    Some(ImportInfo {
                        raw_snippet: raw.trim().to_string(),
                        is_wildcard: false,
                        identifier: Some(identifier.to_string()),
                        alias,
                    })
                })
                .collect();
        }
        if !pattern.is_empty() {
            return vec![ImportInfo {
                raw_snippet: raw.trim().to_string(),
                is_wildcard: false,
                identifier: Some(pattern.to_string()),
                alias: None,
            }];
        }
    }
    Vec::new()
}

fn extract_require_statement(node: Node<'_>, source: &str) -> Option<String> {
    let text = node_text(node, source).trim();
    text.contains("require(").then(|| text.to_string())
}

pub(crate) fn resolve_js_ts_import_paths(
    source_file: &ProjectFile,
    raw_import: &str,
    language: Language,
) -> Vec<ProjectFile> {
    let Some(module_path) = extract_import_module_path(raw_import) else {
        return Vec::new();
    };
    if !module_path.starts_with('.') {
        return Vec::new();
    }
    let base = source_file.parent().join(module_path);
    let mut candidates = Vec::new();
    let exts = language.extensions();
    collect_candidate_paths(source_file.root(), &base, exts, &mut candidates);
    candidates.sort();
    candidates.dedup();
    candidates
}

fn extract_import_module_path(raw_import: &str) -> Option<String> {
    let trimmed = raw_import.trim().trim_end_matches(';').trim();
    if trimmed.starts_with("import ") {
        if let Some((_, path)) = trimmed.trim_end_matches(';').rsplit_once(" from ") {
            return Some(path.trim().trim_matches('\'').trim_matches('"').to_string());
        }
        let path = trimmed.split_whitespace().nth(1)?;
        return Some(path.trim().trim_matches('\'').trim_matches('"').to_string());
    }
    let require = trimmed.split_once("require(")?.1;
    let path = require
        .trim()
        .trim_start_matches('(')
        .trim_end_matches(')')
        .trim_end_matches(';')
        .trim();
    Some(path.trim_matches('\'').trim_matches('"').to_string())
}

fn collect_candidate_paths(
    root: &Path,
    module_path: &Path,
    extensions: &[&str],
    out: &mut Vec<ProjectFile>,
) {
    if module_path.extension().is_some() {
        let file = ProjectFile::new(root.to_path_buf(), module_path.to_path_buf());
        if file.exists() {
            out.push(file);
        }
        return;
    }
    for extension in extensions {
        let with_ext = module_path.with_extension(extension);
        let direct = ProjectFile::new(root.to_path_buf(), with_ext);
        if direct.exists() {
            out.push(direct);
        }
        let index = module_path.join(format!("index.{extension}"));
        let index_file = ProjectFile::new(root.to_path_buf(), index);
        if index_file.exists() {
            out.push(index_file);
        }
    }
}

pub(crate) fn imported_tokens(raw_import: &str) -> BTreeSet<String> {
    parse_js_import_infos(raw_import)
        .into_iter()
        .filter_map(|import| import.alias.or(import.identifier))
        .collect()
}

pub(crate) fn extract_js_ts_call_receiver(reference: &str) -> Option<String> {
    let trimmed = reference.trim();
    let before_args = trimmed
        .split_once('(')
        .map(|(head, _)| head)
        .unwrap_or(trimmed);
    let (receiver, method) = before_args.rsplit_once('.')?;
    if receiver.is_empty() || method.is_empty() {
        return None;
    }
    Some(receiver.to_string())
}

fn extract_js_type_identifiers(source: &str) -> BTreeSet<String> {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_javascript::LANGUAGE.into())
        .expect("failed to load javascript parser");
    let Some(tree) = parser.parse(source, None) else {
        return BTreeSet::new();
    };
    let mut identifiers = BTreeSet::new();
    collect_js_ts_identifiers(tree.root_node(), source, &mut identifiers);
    identifiers
}

pub(crate) fn collect_js_ts_identifiers(
    node: Node<'_>,
    source: &str,
    identifiers: &mut BTreeSet<String>,
) {
    match node.kind() {
        "identifier" | "type_identifier" | "property_identifier" => {
            let text = node_text(node, source).trim();
            if !text.is_empty() {
                identifiers.insert(text.to_string());
            }
        }
        "jsx_opening_element" | "jsx_self_closing_element" => {
            if let Some(name) = node.child_by_field_name("name") {
                let text = node_text(name, source)
                    .trim()
                    .split('.')
                    .next_back()
                    .unwrap_or("");
                if !text.is_empty() {
                    identifiers.insert(text.to_string());
                }
            }
        }
        _ => {}
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        collect_js_ts_identifiers(child, source, identifiers);
    }
}

fn node_returns_jsx(node: Node<'_>, source: &str) -> bool {
    if matches!(
        node.kind(),
        "jsx_element" | "jsx_self_closing_element" | "jsx_fragment"
    ) {
        return true;
    }

    let text = node_text(node, source);
    text.contains('<') && (text.contains("/>") || text.contains("</"))
}

fn is_component_like_name(name: &str) -> bool {
    name.chars()
        .next()
        .map(|ch| ch.is_ascii_uppercase())
        .unwrap_or(false)
}

fn js_ts_contains_tests(file: &ProjectFile, source: &str) -> bool {
    let rel = file.rel_path().to_string_lossy().to_ascii_lowercase();
    rel.contains(".test.")
        || rel.contains(".spec.")
        || source.contains("describe(")
        || source.contains("test(")
        || source.contains("it(")
}

pub(crate) fn build_weighted_cache<K, V>(
    budget_bytes: u64,
    weigher: impl Fn(&K, &V) -> u32 + Send + Sync + 'static,
) -> Cache<K, V>
where
    K: Clone + Eq + std::hash::Hash + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
{
    Cache::builder()
        .max_capacity(budget_bytes.max(1))
        .weigher(weigher)
        .build()
}

fn weight_string_set(_key: &CodeUnit, value: &Arc<BTreeSet<String>>) -> u32 {
    let size = value
        .iter()
        .map(|item| item.len() + size_of::<String>())
        .sum::<usize>()
        + size_of::<BTreeSet<String>>();
    size.min(u32::MAX as usize) as u32
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
