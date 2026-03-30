use crate::analyzer::{
    AnalyzerConfig, CodeUnit, IAnalyzer, ImportAnalysisProvider, ImportInfo, Language, Project,
    ProjectFile, TestDetectionProvider, TreeSitterAnalyzer, TypeAliasProvider,
    referencing_files_via_imports,
};
use moka::sync::Cache;
use std::collections::BTreeSet;
use std::mem::size_of;
use std::sync::Arc;
use tree_sitter::{Language as TsLanguage, Node, Parser, Tree};

use super::javascript_analyzer::{
    build_weighted_cache, extract_js_ts_call_receiver, imported_tokens, module_code_unit,
    node_text, parse_js_import_infos, resolve_js_ts_import_paths, trim_statement,
};

#[derive(Debug, Clone, Default)]
pub struct TypescriptAdapter;

impl crate::analyzer::LanguageAdapter for TypescriptAdapter {
    fn language(&self) -> Language {
        Language::TypeScript
    }

    fn query_directory(&self) -> &'static str {
        "resources/treesitter/typescript"
    }

    fn parser_language(&self) -> TsLanguage {
        tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into()
    }

    fn file_extension(&self) -> &'static str {
        "ts"
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
        let rel = file.rel_path().to_string_lossy().to_ascii_lowercase();
        rel.contains(".test.")
            || rel.contains(".spec.")
            || source.contains("describe(")
            || source.contains("test(")
            || source.contains("it(")
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
                    let raw = node_text(child, source).trim();
                    if raw.contains("require(") {
                        module_has_imports = true;
                        parsed.import_statements.push(raw.to_string());
                        parsed.imports.extend(parse_js_import_infos(raw));
                    }
                }
                "export_statement" => visit_ts_export(file, source, child, None, &mut parsed),
                "class_declaration"
                | "abstract_class_declaration"
                | "interface_declaration"
                | "enum_declaration"
                | "internal_module" => {
                    visit_ts_class_like(file, source, child, None, &mut parsed, false);
                }
                "function_declaration" | "function_signature" => {
                    visit_ts_function(file, source, child, None, &mut parsed, false);
                }
                "lexical_declaration" | "variable_declaration" | "type_alias_declaration" => {
                    if matches!(child.kind(), "lexical_declaration" | "variable_declaration") {
                        let raw = node_text(child, source).trim();
                        if raw.contains("require(") {
                            module_has_imports = true;
                            parsed.import_statements.push(raw.to_string());
                            parsed.imports.extend(parse_js_import_infos(raw));
                        }
                    }
                    visit_ts_value(file, source, child, None, &mut parsed, false);
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
pub struct TypescriptAnalyzer {
    inner: TreeSitterAnalyzer<TypescriptAdapter>,
    memo_budget: u64,
    imported_code_units: Cache<ProjectFile, Arc<BTreeSet<CodeUnit>>>,
    referencing_files: Cache<ProjectFile, Arc<BTreeSet<ProjectFile>>>,
    relevant_imports: Cache<CodeUnit, Arc<BTreeSet<String>>>,
}

impl TypescriptAnalyzer {
    pub fn new(project: Arc<dyn Project>) -> Self {
        Self::new_with_config(project, AnalyzerConfig::default())
    }

    pub fn new_with_config(project: Arc<dyn Project>, config: AnalyzerConfig) -> Self {
        let memo_budget = config.memo_cache_budget_bytes();
        Self {
            inner: TreeSitterAnalyzer::new_with_config(project, TypescriptAdapter, config),
            memo_budget,
            imported_code_units: build_weighted_cache(memo_budget / 3, weight_code_unit_set),
            referencing_files: build_weighted_cache(memo_budget / 6, weight_project_file_set),
            relevant_imports: build_weighted_cache(memo_budget / 6, weight_string_set),
        }
    }

    pub fn from_project<P>(project: P) -> Self
    where
        P: Project + 'static,
    {
        Self::new(Arc::new(project))
    }

    pub fn is_type_alias(&self, code_unit: &CodeUnit) -> bool {
        self.inner.is_type_alias(code_unit)
    }

    pub fn extract_type_identifiers(&self, source: &str) -> BTreeSet<String> {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into())
            .expect("failed to load typescript parser");
        let Some(tree) = parser.parse(source, None) else {
            return BTreeSet::new();
        };
        let mut identifiers = BTreeSet::new();
        super::javascript_analyzer::collect_js_ts_identifiers(
            tree.root_node(),
            source,
            &mut identifiers,
        );
        identifiers
    }
}

impl ImportAnalysisProvider for TypescriptAnalyzer {
    fn imported_code_units_of(&self, file: &ProjectFile) -> BTreeSet<CodeUnit> {
        if let Some(cached) = self.imported_code_units.get(file) {
            return (*cached).clone();
        }

        let mut resolved = BTreeSet::new();
        for import in self.inner.import_info_of(file) {
            for target in
                resolve_js_ts_import_paths(file, &import.raw_snippet, Language::TypeScript)
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

        self.imported_code_units
            .insert(file.clone(), Arc::new(resolved.clone()));
        resolved
    }

    fn referencing_files_of(&self, file: &ProjectFile) -> BTreeSet<ProjectFile> {
        if let Some(cached) = self.referencing_files.get(file) {
            return (*cached).clone();
        }

        let referencing = referencing_files_via_imports(self, self, file);
        self.referencing_files
            .insert(file.clone(), Arc::new(referencing.clone()));
        referencing
    }

    fn import_info_of(&self, file: &ProjectFile) -> Vec<ImportInfo> {
        self.inner.import_info_of(file)
    }

    fn relevant_imports_for(&self, code_unit: &CodeUnit) -> BTreeSet<String> {
        if let Some(cached) = self.relevant_imports.get(code_unit) {
            return (*cached).clone();
        }
        let source = self.inner.get_source(code_unit, false).unwrap_or_default();
        let relevant: BTreeSet<_> = self
            .inner
            .import_info_of(code_unit.source())
            .into_iter()
            .filter(|import| {
                let tokens = imported_tokens(&import.raw_snippet);
                tokens.is_empty() || tokens.iter().any(|token| source.contains(token))
            })
            .map(|import| import.raw_snippet)
            .collect();
        self.relevant_imports
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
            resolve_js_ts_import_paths(source_file, &import.raw_snippet, Language::TypeScript)
                .into_iter()
                .any(|candidate| candidate == *target)
        })
    }
}

impl TypeAliasProvider for TypescriptAnalyzer {
    fn is_type_alias(&self, code_unit: &CodeUnit) -> bool {
        self.inner.is_type_alias(code_unit)
    }
}

impl TestDetectionProvider for TypescriptAnalyzer {}

impl IAnalyzer for TypescriptAnalyzer {
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
            imported_code_units: build_weighted_cache(self.memo_budget / 3, weight_code_unit_set),
            referencing_files: build_weighted_cache(self.memo_budget / 6, weight_project_file_set),
            relevant_imports: build_weighted_cache(self.memo_budget / 6, weight_string_set),
        }
    }
    fn update_all(&self) -> Self {
        Self {
            inner: self.inner.update_all(),
            memo_budget: self.memo_budget,
            imported_code_units: build_weighted_cache(self.memo_budget / 3, weight_code_unit_set),
            referencing_files: build_weighted_cache(self.memo_budget / 6, weight_project_file_set),
            relevant_imports: build_weighted_cache(self.memo_budget / 6, weight_string_set),
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
    fn signatures_of(&self, code_unit: &CodeUnit) -> Vec<String> {
        self.inner
            .signatures_of(code_unit)
            .into_iter()
            .map(|signature| {
                if self.inner.is_type_alias(code_unit) && !signature.ends_with(';') {
                    format!("{signature};")
                } else {
                    signature
                }
            })
            .collect()
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
}

fn visit_ts_export(
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    parent: Option<&CodeUnit>,
    parsed: &mut crate::analyzer::tree_sitter_analyzer::ParsedFile,
) {
    if let Some(declaration) = node.child_by_field_name("declaration") {
        match declaration.kind() {
            "class_declaration"
            | "abstract_class_declaration"
            | "interface_declaration"
            | "enum_declaration"
            | "internal_module" => {
                visit_ts_class_like(file, source, node, parent, parsed, true);
            }
            "function_declaration" | "function_signature" => {
                visit_ts_function(file, source, node, parent, parsed, true);
            }
            "lexical_declaration" | "variable_declaration" | "type_alias_declaration" => {
                visit_ts_value(file, source, node, parent, parsed, true);
            }
            _ => {}
        }
    }
}

fn visit_ts_class_like(
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
    let name = trim_statement(node_text(name_node, source));
    if name.is_empty() {
        return None;
    }
    let short_name = parent
        .map(|parent| format!("{}.{}", parent.short_name(), name))
        .unwrap_or(name.clone());
    let code_unit = CodeUnit::new(
        file.clone(),
        crate::analyzer::CodeUnitType::Class,
        "",
        short_name,
    );
    let top_level = parent.cloned().unwrap_or_else(|| code_unit.clone());
    let range_node = if exported { node } else { definition };
    parsed.add_code_unit(
        code_unit.clone(),
        range_node,
        source,
        parent.cloned(),
        Some(top_level.clone()),
    );
    parsed.add_signature(
        code_unit.clone(),
        ts_class_signature(node, source, exported),
    );

    if definition.kind() == "enum_declaration" {
        if let Some(body) = definition.child_by_field_name("body") {
            for index in 0..body.named_child_count() {
                let Some(child) = body.named_child(index) else {
                    continue;
                };
                if child.kind() == "enum_assignment"
                    || child.kind() == "property_identifier"
                    || child.kind() == "identifier"
                {
                    visit_ts_enum_member(file, source, child, &code_unit, &top_level, parsed);
                }
            }
        }
        return Some(code_unit);
    }

    if let Some(body) = definition.child_by_field_name("body") {
        for index in 0..body.named_child_count() {
            let Some(child) = body.named_child(index) else {
                continue;
            };
            match child.kind() {
                "method_definition" | "method_signature" | "abstract_method_signature" => {
                    visit_ts_method(file, source, child, &code_unit, &top_level, parsed);
                }
                "public_field_definition" | "property_signature" | "index_signature" => {
                    visit_ts_field(file, source, child, &code_unit, &top_level, parsed);
                }
                "class_declaration"
                | "interface_declaration"
                | "enum_declaration"
                | "internal_module" => {
                    visit_ts_class_like(file, source, child, Some(&code_unit), parsed, false);
                }
                _ => {}
            }
        }
    }
    Some(code_unit)
}

fn visit_ts_function(
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
    let Some(name_node) = definition.child_by_field_name("name") else {
        return;
    };
    let name = trim_statement(node_text(name_node, source));
    if name.is_empty() {
        return;
    }
    let short_name = parent
        .map(|parent| format!("{}.{}", parent.short_name(), name))
        .unwrap_or(name);
    let code_unit = CodeUnit::new(
        file.clone(),
        crate::analyzer::CodeUnitType::Function,
        "",
        short_name,
    );
    let top_level = parent.cloned().unwrap_or_else(|| code_unit.clone());
    let range_node = if exported { node } else { definition };
    parsed.add_code_unit(
        code_unit.clone(),
        range_node,
        source,
        parent.cloned(),
        Some(top_level),
    );
    parsed.add_signature(code_unit, ts_function_signature(node, source, exported));
}

fn visit_ts_value(
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

    if definition.kind() == "type_alias_declaration" {
        let Some(name_node) = definition.child_by_field_name("name") else {
            return;
        };
        let name = trim_statement(node_text(name_node, source));
        let short_name = parent
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
            });
        let code_unit = CodeUnit::new(
            file.clone(),
            crate::analyzer::CodeUnitType::Field,
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
        parsed.add_signature(code_unit.clone(), trim_statement(node_text(node, source)));
        parsed.mark_type_alias(code_unit);
        return;
    }

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
        let name = trim_statement(node_text(name_node, source));
        let value = child.child_by_field_name("value");
        let is_function = value
            .map(|value| value.kind() == "arrow_function")
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
                .unwrap_or(name)
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
                ts_variable_function_signature(definition, child, source, exported),
            );
        } else {
            parsed.add_signature(
                code_unit,
                ts_variable_signature(definition, child, source, exported),
            );
        }
    }
}

fn visit_ts_method(
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
    let name = trim_statement(node_text(name_node, source))
        .trim_matches('"')
        .to_string();
    let member_name = if is_static_ts_member(node, source) {
        format!("{name}$static")
    } else {
        name
    };
    let code_unit = CodeUnit::new(
        file.clone(),
        crate::analyzer::CodeUnitType::Function,
        "",
        format!("{}.{}", parent.short_name(), member_name),
    );
    parsed.add_code_unit(
        code_unit.clone(),
        node,
        source,
        Some(parent.clone()),
        Some(top_level.clone()),
    );
    parsed.add_signature(
        code_unit,
        match node.kind() {
            "method_definition" => format!(
                "{} {{ ... }}",
                trim_statement(node_text(node, source).split('{').next().unwrap_or(""))
            ),
            _ => trim_statement(node_text(node, source).split('{').next().unwrap_or("")),
        },
    );
}

fn visit_ts_field(
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    parent: &CodeUnit,
    top_level: &CodeUnit,
    parsed: &mut crate::analyzer::tree_sitter_analyzer::ParsedFile,
) {
    let name_node = node.child_by_field_name("name").unwrap_or(node);
    let name = trim_statement(node_text(name_node, source))
        .trim_matches('"')
        .to_string();
    let member_name = if is_static_ts_member(node, source) {
        format!("{name}$static")
    } else {
        name
    };
    let code_unit = CodeUnit::new(
        file.clone(),
        crate::analyzer::CodeUnitType::Field,
        "",
        format!("{}.{}", parent.short_name(), member_name),
    );
    parsed.add_code_unit(
        code_unit.clone(),
        node,
        source,
        Some(parent.clone()),
        Some(top_level.clone()),
    );
    parsed.add_signature(code_unit, ts_field_signature(node, source));
}

fn visit_ts_enum_member(
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    parent: &CodeUnit,
    top_level: &CodeUnit,
    parsed: &mut crate::analyzer::tree_sitter_analyzer::ParsedFile,
) {
    let name = if node.kind() == "enum_assignment" {
        node.child_by_field_name("name")
            .map(|name| trim_statement(node_text(name, source)))
            .unwrap_or_default()
    } else {
        trim_statement(node_text(node, source))
    };
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
    let raw = trim_statement(node_text(node, source));
    let suffix = source
        .get(node.end_byte()..)
        .map(str::trim_start)
        .filter(|tail| tail.starts_with(','))
        .map(|_| ",")
        .unwrap_or("");
    parsed.add_signature(code_unit, format!("{raw}{suffix}"));
}

fn ts_class_signature(node: Node<'_>, source: &str, exported: bool) -> String {
    let definition = if node.kind() == "export_statement" {
        node.child_by_field_name("declaration").unwrap_or(node)
    } else {
        node
    };
    let text = if node.kind() == "export_statement" {
        node_text(node, source)
    } else {
        node_text(definition, source)
    };
    let head = trim_statement(text.split('{').next().unwrap_or(text));
    if definition.kind() == "enum_declaration" {
        let open = format!(
            "{} {{",
            if exported && !head.starts_with("export ") {
                format!("export {head}")
            } else {
                head
            }
        );
        return open;
    }
    format!(
        "{} {{",
        if exported && !head.starts_with("export ") {
            format!("export {head}")
        } else {
            head
        }
    )
}

fn ts_function_signature(node: Node<'_>, source: &str, exported: bool) -> String {
    let definition = if node.kind() == "export_statement" {
        node.child_by_field_name("declaration").unwrap_or(node)
    } else {
        node
    };
    let head = trim_statement(
        if node.kind() == "export_statement" {
            node_text(node, source)
        } else {
            node_text(definition, source)
        }
        .split('{')
        .next()
        .unwrap_or(node_text(definition, source)),
    );
    let head = if exported && !head.starts_with("export ") {
        format!("export {head}")
    } else {
        head
    };
    if definition.kind() == "function_signature" {
        head
    } else {
        format!("{head} {{ ... }}")
    }
}

fn ts_variable_function_signature(
    statement: Node<'_>,
    declarator: Node<'_>,
    source: &str,
    exported: bool,
) -> String {
    let kind = statement
        .child(0)
        .map(|node| node_text(node, source).trim().to_string())
        .unwrap_or_else(|| "const".to_string());
    let name = declarator
        .child_by_field_name("name")
        .map(|node| trim_statement(node_text(node, source)))
        .unwrap_or_default();
    let value = declarator
        .child_by_field_name("value")
        .unwrap_or(declarator);
    let params = value
        .child_by_field_name("parameters")
        .map(|node| trim_statement(node_text(node, source)))
        .unwrap_or_else(|| "()".to_string());
    let return_type = value
        .child_by_field_name("return_type")
        .map(|node| trim_statement(node_text(node, source)))
        .unwrap_or_default();
    let export_prefix = if exported { "export " } else { "" };
    let return_suffix = if return_type.is_empty() {
        String::new()
    } else {
        format!(": {}", return_type.trim_start_matches(':').trim())
    };
    format!("{export_prefix}{kind} {name} = {params}{return_suffix} => {{ ... }}")
}

fn ts_variable_signature(
    statement: Node<'_>,
    declarator: Node<'_>,
    source: &str,
    exported: bool,
) -> String {
    let header = ts_variable_header(statement, declarator, source, exported);
    match declarator.child_by_field_name("value") {
        Some(value) if is_simple_ts_initializer(value) => {
            let value_text = trim_statement(node_text(value, source));
            format!("{header} = {value_text}")
        }
        _ => header,
    }
}

fn ts_field_signature(node: Node<'_>, source: &str) -> String {
    if matches!(node.kind(), "property_signature" | "index_signature") {
        return trim_statement(node_text(node, source));
    }

    let raw = trim_statement(node_text(node, source));
    if let Some(value) = node.child_by_field_name("value")
        && !is_simple_ts_initializer(value)
    {
        return raw
            .split('=')
            .next()
            .map(trim_statement)
            .filter(|header| !header.is_empty())
            .unwrap_or(raw);
    }
    raw
}

fn ts_variable_header(
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

fn is_simple_ts_initializer(node: Node<'_>) -> bool {
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
    )
}

fn is_static_ts_member(node: Node<'_>, source: &str) -> bool {
    let head = node_text(node, source)
        .split(['{', ';'])
        .next()
        .unwrap_or("");
    head.split_whitespace().any(|token| token == "static")
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
