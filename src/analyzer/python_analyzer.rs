use crate::analyzer::{
    AnalyzerConfig, CodeUnit, CodeUnitType, IAnalyzer, ImportAnalysisProvider, ImportInfo,
    Language, LanguageAdapter, Project, ProjectFile, TestDetectionProvider, TreeSitterAnalyzer,
    TypeHierarchyProvider, direct_descendants_via_ancestors,
};
use crate::profiling;
use crate::text_utils::{compute_line_starts, find_line_index_for_offset};
use moka::sync::Cache;
use rayon::prelude::*;
use regex::Regex;
use std::collections::{BTreeMap, BTreeSet};
use std::mem::size_of;
use std::path::Path;
use std::sync::{Arc, OnceLock};
use tree_sitter::{Language as TsLanguage, Node, Parser, Tree};

use super::javascript_analyzer::build_weighted_cache;

#[derive(Debug, Clone, Default)]
pub struct PythonAdapter;

impl LanguageAdapter for PythonAdapter {
    fn language(&self) -> Language {
        Language::Python
    }

    fn query_directory(&self) -> &'static str {
        "resources/treesitter/python"
    }

    fn parser_language(&self) -> TsLanguage {
        tree_sitter_python::LANGUAGE.into()
    }

    fn file_extension(&self) -> &'static str {
        "py"
    }

    fn contains_tests(
        &self,
        _file: &ProjectFile,
        source: &str,
        _tree: &Tree,
        _parsed: &crate::analyzer::tree_sitter_analyzer::ParsedFile,
    ) -> bool {
        python_source_contains_tests(source)
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
        let module_fq = python_module_name(file);
        let mut parsed = crate::analyzer::tree_sitter_analyzer::ParsedFile::new(module_fq.clone());
        let root = tree.root_node();

        collect_python_identifiers(root, source, &mut parsed.type_identifiers);

        let module_code_unit = module_code_unit(file, &module_fq);
        if let Some(module) = module_code_unit.clone() {
            parsed.add_code_unit(module, root, source, None, None);
        }

        let mut visitor = PythonVisitor {
            file,
            source,
            package_name: &module_fq,
            parsed: &mut parsed,
            module: module_code_unit,
        };
        visitor.visit_container(root, &[], 0);

        parsed
    }
}

#[derive(Clone)]
pub struct PythonAnalyzer {
    inner: TreeSitterAnalyzer<PythonAdapter>,
    memo_budget: u64,
    imported_code_units: Cache<ProjectFile, Arc<BTreeSet<CodeUnit>>>,
    referencing_files: Cache<ProjectFile, Arc<BTreeSet<ProjectFile>>>,
    direct_ancestors: Cache<CodeUnit, Arc<Vec<CodeUnit>>>,
    direct_descendants: Cache<CodeUnit, Arc<BTreeSet<CodeUnit>>>,
    module_code_units: Arc<BTreeMap<String, CodeUnit>>,
    reverse_import_index: Arc<OnceLock<BTreeMap<ProjectFile, Arc<BTreeSet<ProjectFile>>>>>,
}

impl PythonAnalyzer {
    pub fn new(project: Arc<dyn Project>) -> Self {
        Self::new_with_config(project, AnalyzerConfig::default())
    }

    pub fn new_with_config(project: Arc<dyn Project>, config: AnalyzerConfig) -> Self {
        let memo_budget = config.memo_cache_budget_bytes();
        let inner = TreeSitterAnalyzer::new_with_config(project, PythonAdapter, config);
        Self {
            module_code_units: Arc::new(build_python_module_code_units(&inner)),
            inner,
            memo_budget,
            imported_code_units: build_weighted_cache(memo_budget / 4, weight_code_unit_set),
            referencing_files: build_weighted_cache(memo_budget / 8, weight_project_file_set),
            direct_ancestors: build_weighted_cache(memo_budget / 8, weight_code_unit_vec),
            direct_descendants: build_weighted_cache(memo_budget / 8, weight_code_unit_set_by_unit),
            reverse_import_index: Arc::new(OnceLock::new()),
        }
    }

    pub fn from_project<P>(project: P) -> Self
    where
        P: Project + 'static,
    {
        Self::new(Arc::new(project))
    }

    fn extract_type_identifiers(&self, source: &str) -> BTreeSet<String> {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_python::LANGUAGE.into())
            .expect("failed to load python parser");
        let Some(tree) = parser.parse(source, None) else {
            return BTreeSet::new();
        };
        let mut identifiers = BTreeSet::new();
        collect_python_identifiers(tree.root_node(), source, &mut identifiers);
        identifiers
    }

    fn resolve_import_bindings(&self, file: &ProjectFile) -> BTreeMap<String, CodeUnit> {
        let mut bindings = BTreeMap::new();
        for import in self.inner.import_info_of(file) {
            for (binding, code_unit) in self.resolve_import(file, &import) {
                bindings.insert(binding, code_unit);
            }
        }
        bindings
    }

    fn resolve_import(&self, file: &ProjectFile, import: &ImportInfo) -> Vec<(String, CodeUnit)> {
        if let Some(details) = parse_python_import_details(&import.raw_snippet) {
            match details {
                PythonImportDetails::Import { module, alias } => {
                    if let Some(module_code_unit) = self.resolve_module_code_unit(&module) {
                        let binding = alias.unwrap_or_else(|| {
                            module
                                .split('.')
                                .next_back()
                                .unwrap_or(module.as_str())
                                .to_string()
                        });
                        return vec![(binding, module_code_unit)];
                    }
                }
                PythonImportDetails::FromImport {
                    module,
                    name,
                    alias,
                    wildcard,
                } => {
                    let resolved_module = if module.starts_with('.') {
                        resolve_python_relative_module(file, &module)
                    } else {
                        Some(module)
                    };
                    let Some(resolved_module) = resolved_module else {
                        return Vec::new();
                    };
                    if wildcard {
                        return self
                            .public_declarations_in_module(&resolved_module)
                            .into_iter()
                            .map(|code_unit| (code_unit.identifier().to_string(), code_unit))
                            .collect();
                    }

                    let binding = alias.clone().unwrap_or_else(|| name.clone());
                    let module_candidate = format!("{resolved_module}.{name}");
                    if let Some(code_unit) = self.resolve_module_code_unit(&module_candidate) {
                        return vec![(binding, code_unit)];
                    }
                    let definitions = self.inner.get_definitions(&module_candidate);
                    if !definitions.is_empty() {
                        return definitions
                            .into_iter()
                            .map(|code_unit| (binding.clone(), code_unit))
                            .collect();
                    }
                    let package_candidate = self
                        .inner
                        .get_definitions(&format!("{resolved_module}.{name}"));
                    if !package_candidate.is_empty() {
                        return package_candidate
                            .into_iter()
                            .map(|code_unit| (binding.clone(), code_unit))
                            .collect();
                    }
                }
            }
        }
        Vec::new()
    }

    fn resolve_module_code_unit(&self, module_fq: &str) -> Option<CodeUnit> {
        self.inner
            .get_definitions(module_fq)
            .into_iter()
            .find(|code_unit| code_unit.is_module())
            .or_else(|| self.module_code_units.get(module_fq).cloned())
    }

    fn build_reverse_import_index(&self) -> &BTreeMap<ProjectFile, Arc<BTreeSet<ProjectFile>>> {
        self.reverse_import_index.get_or_init(|| {
            let _scope = profiling::scope("PythonAnalyzer::build_reverse_import_index");
            let files: Vec<_> = self.inner.get_analyzed_files().into_iter().collect();
            let imported_by_file: Vec<_> = files
                .par_iter()
                .map(|file| {
                    let resolved: BTreeSet<_> =
                        self.resolve_import_bindings(file).into_values().collect();
                    (file.clone(), resolved)
                })
                .collect();

            let mut reverse: BTreeMap<ProjectFile, BTreeSet<ProjectFile>> = BTreeMap::new();
            for (file, imported) in imported_by_file {
                self.imported_code_units
                    .insert(file.clone(), Arc::new(imported.clone()));
                for code_unit in imported {
                    let target = code_unit.source();
                    if target != &file {
                        reverse
                            .entry(target.clone())
                            .or_default()
                            .insert(file.clone());
                    }
                }
            }

            if profiling::enabled() {
                profiling::note(format!(
                    "PythonAnalyzer::build_reverse_import_index files={} indexed_targets={}",
                    files.len(),
                    reverse.len()
                ));
            }

            reverse
                .into_iter()
                .map(|(file, refs)| (file, Arc::new(refs)))
                .collect()
        })
    }

    fn public_declarations_in_module(&self, module_fq: &str) -> Vec<CodeUnit> {
        let Some(module_code_unit) = self.resolve_module_code_unit(module_fq) else {
            return Vec::new();
        };
        self.inner
            .get_direct_children(&module_code_unit)
            .into_iter()
            .filter(|code_unit| !code_unit.identifier().starts_with('_'))
            .collect()
    }

    fn resolve_base_class(&self, code_unit: &CodeUnit, raw: &str) -> Option<CodeUnit> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return None;
        }

        let bindings = self.resolve_import_bindings(code_unit.source());
        if let Some((head, tail)) = trimmed.split_once('.') {
            if let Some(bound) = bindings.get(head)
                && bound.is_module()
            {
                let fq_name = format!("{}.{}", bound.fq_name(), tail);
                return self.inner.get_definitions(&fq_name).into_iter().next();
            }
            return self.inner.get_definitions(trimmed).into_iter().next();
        }

        if let Some(bound) = bindings.get(trimmed) {
            return Some(bound.clone());
        }

        let local_fq_name = format!("{}.{}", code_unit.package_name(), trimmed);
        self.inner
            .get_definitions(&local_fq_name)
            .into_iter()
            .next()
            .or_else(|| self.inner.get_definitions(trimmed).into_iter().next())
    }

    fn render_skeleton_recursive(
        &self,
        code_unit: &CodeUnit,
        indent: &str,
        header_only: bool,
        out: &mut String,
    ) {
        if let Some(signature) = self.python_signature(code_unit, header_only) {
            for line in signature.lines() {
                out.push_str(indent);
                out.push_str(line);
                out.push('\n');
            }
        }

        let all_children = self.inner.get_direct_children(code_unit);
        let field_children: Vec<_> = all_children
            .iter()
            .filter(|child| child.is_field())
            .cloned()
            .collect();
        let children = if header_only {
            field_children.clone()
        } else {
            all_children.clone()
        };
        if !children.is_empty() || code_unit.is_class() || code_unit.is_module() {
            let child_indent = format!("{indent}  ");
            for child in children {
                self.render_skeleton_recursive(&child, &child_indent, header_only, out);
            }
            if header_only && all_children.len() > field_children.len() {
                out.push_str(&child_indent);
                out.push_str("[...]\n");
            }
        }
    }

    fn python_signature(&self, code_unit: &CodeUnit, _header_only: bool) -> Option<String> {
        if code_unit.is_module() {
            return None;
        }

        let source = self.inner.get_source(code_unit, false)?;
        let lines: Vec<_> = source
            .lines()
            .map(str::trim_end)
            .filter(|line| !line.trim().is_empty())
            .collect();
        if lines.is_empty() {
            return None;
        }

        let mut decorators = Vec::new();
        let mut header = None;
        for line in lines {
            let trimmed = line.trim_start();
            if trimmed.starts_with('@') {
                decorators.push(trimmed.to_string());
                continue;
            }
            header = Some(trimmed.to_string());
            break;
        }
        let mut rendered = String::new();
        for decorator in decorators {
            rendered.push_str(&decorator);
            rendered.push('\n');
        }

        let header = header?;
        match code_unit.kind() {
            CodeUnitType::Class => rendered.push_str(&header),
            CodeUnitType::Function => {
                rendered.push_str(header.trim_end_matches(':'));
                rendered.push_str(": ...");
            }
            CodeUnitType::Field => rendered.push_str(header.as_str()),
            CodeUnitType::Module => return None,
        }
        Some(rendered)
    }
}

impl ImportAnalysisProvider for PythonAnalyzer {
    fn imported_code_units_of(&self, file: &ProjectFile) -> BTreeSet<CodeUnit> {
        if let Some(cached) = self.imported_code_units.get(file) {
            return (*cached).clone();
        }

        let resolved: BTreeSet<_> = self.resolve_import_bindings(file).into_values().collect();
        self.imported_code_units
            .insert(file.clone(), Arc::new(resolved.clone()));
        resolved
    }

    fn referencing_files_of(&self, file: &ProjectFile) -> BTreeSet<ProjectFile> {
        if let Some(cached) = self.referencing_files.get(file) {
            return (*cached).clone();
        }

        let referencing = self
            .build_reverse_import_index()
            .get(file)
            .map(|files| (**files).clone())
            .unwrap_or_default();
        self.referencing_files
            .insert(file.clone(), Arc::new(referencing.clone()));
        referencing
    }

    fn import_info_of(&self, file: &ProjectFile) -> Vec<ImportInfo> {
        self.inner.import_info_of(file)
    }

    fn relevant_imports_for(&self, code_unit: &CodeUnit) -> BTreeSet<String> {
        let Some(source) = self.inner.get_source(code_unit, false) else {
            return BTreeSet::new();
        };

        let extracted = self.extract_type_identifiers(&source);
        if extracted.is_empty() {
            return BTreeSet::new();
        }

        let imports = self.inner.import_info_of(code_unit.source());
        if imports.is_empty() {
            return BTreeSet::new();
        }

        let mut matched = BTreeSet::new();
        let mut resolved = BTreeSet::new();
        let mut wildcard_imports = Vec::new();

        for info in &imports {
            if info.is_wildcard {
                wildcard_imports.push(info.clone());
                continue;
            }

            if let Some(identifier) = info.identifier.as_deref()
                && extracted.contains(identifier)
            {
                matched.insert(info.raw_snippet.clone());
                resolved.insert(identifier.to_string());
            }

            if let Some(alias) = info.alias.as_deref()
                && extracted.contains(alias)
            {
                matched.insert(info.raw_snippet.clone());
                resolved.insert(alias.to_string());
            }
        }

        let unresolved: BTreeSet<_> = extracted.difference(&resolved).cloned().collect();
        if unresolved.is_empty() || wildcard_imports.is_empty() {
            return matched;
        }

        let mut resolved_via_wildcard = BTreeSet::new();
        let mut used_wildcards = BTreeSet::new();
        for ident in &unresolved {
            for wildcard in &wildcard_imports {
                let Some(package_name) =
                    extract_package_from_python_wildcard(&wildcard.raw_snippet)
                else {
                    continue;
                };

                if !self
                    .inner
                    .get_definitions(&format!("{package_name}.{ident}"))
                    .is_empty()
                {
                    used_wildcards.insert(wildcard.raw_snippet.clone());
                    resolved_via_wildcard.insert(ident.clone());
                }
            }
        }

        matched.extend(used_wildcards);

        let remaining: BTreeSet<_> = unresolved
            .difference(&resolved_via_wildcard)
            .cloned()
            .collect();
        if !remaining.is_empty() {
            matched.extend(wildcard_imports.into_iter().map(|info| info.raw_snippet));
        }

        matched
    }

    fn could_import_file(
        &self,
        source_file: &ProjectFile,
        imports: &[ImportInfo],
        target: &ProjectFile,
    ) -> bool {
        for import in imports {
            let Some(details) = parse_python_import_details(&import.raw_snippet) else {
                continue;
            };
            match details {
                PythonImportDetails::FromImport { module, name, .. } if module.starts_with('.') => {
                    let Some(resolved_module) =
                        resolve_python_relative_module(source_file, &module)
                    else {
                        return true;
                    };
                    let candidate_module = format!("{resolved_module}.{name}");
                    if python_module_name(target) == candidate_module
                        || python_module_name(target) == resolved_module
                    {
                        return true;
                    }
                }
                _ => {
                    if self
                        .resolve_import(source_file, import)
                        .into_iter()
                        .any(|(_, code_unit)| code_unit.source() == target)
                    {
                        return true;
                    }
                }
            }
        }
        false
    }
}

impl TypeHierarchyProvider for PythonAnalyzer {
    fn get_direct_ancestors(&self, code_unit: &CodeUnit) -> Vec<CodeUnit> {
        if let Some(cached) = self.direct_ancestors.get(code_unit) {
            return (*cached).clone();
        }

        let ancestors: Vec<_> = self
            .inner
            .raw_supertypes_of(code_unit)
            .into_iter()
            .filter_map(|raw| self.resolve_base_class(code_unit, &raw))
            .collect();
        self.direct_ancestors
            .insert(code_unit.clone(), Arc::new(ancestors.clone()));
        ancestors
    }

    fn get_direct_descendants(&self, code_unit: &CodeUnit) -> BTreeSet<CodeUnit> {
        if let Some(cached) = self.direct_descendants.get(code_unit) {
            return (*cached).clone();
        }

        let descendants = direct_descendants_via_ancestors(self, self, code_unit);
        self.direct_descendants
            .insert(code_unit.clone(), Arc::new(descendants.clone()));
        descendants
    }
}

impl TestDetectionProvider for PythonAnalyzer {}

impl IAnalyzer for PythonAnalyzer {
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
        let inner = self.inner.update(changed_files);
        Self {
            module_code_units: Arc::new(build_python_module_code_units(&inner)),
            inner,
            memo_budget: self.memo_budget,
            imported_code_units: build_weighted_cache(self.memo_budget / 4, weight_code_unit_set),
            referencing_files: build_weighted_cache(self.memo_budget / 8, weight_project_file_set),
            direct_ancestors: build_weighted_cache(self.memo_budget / 8, weight_code_unit_vec),
            direct_descendants: build_weighted_cache(
                self.memo_budget / 8,
                weight_code_unit_set_by_unit,
            ),
            reverse_import_index: Arc::new(OnceLock::new()),
        }
    }

    fn update_all(&self) -> Self {
        let inner = self.inner.update_all();
        Self {
            module_code_units: Arc::new(build_python_module_code_units(&inner)),
            inner,
            memo_budget: self.memo_budget,
            imported_code_units: build_weighted_cache(self.memo_budget / 4, weight_code_unit_set),
            referencing_files: build_weighted_cache(self.memo_budget / 8, weight_project_file_set),
            direct_ancestors: build_weighted_cache(self.memo_budget / 8, weight_code_unit_vec),
            direct_descendants: build_weighted_cache(
                self.memo_budget / 8,
                weight_code_unit_set_by_unit,
            ),
            reverse_import_index: Arc::new(OnceLock::new()),
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
        let mut rendered = String::new();
        self.render_skeleton_recursive(code_unit, "", false, &mut rendered);
        let trimmed = rendered.trim_end();
        (!trimmed.is_empty()).then(|| trimmed.to_string())
    }

    fn get_skeleton_header(&self, code_unit: &CodeUnit) -> Option<String> {
        let mut rendered = String::new();
        self.render_skeleton_recursive(code_unit, "", true, &mut rendered);
        let trimmed = rendered.trim_end();
        (!trimmed.is_empty()).then(|| trimmed.to_string())
    }

    fn get_source(&self, code_unit: &CodeUnit, include_comments: bool) -> Option<String> {
        let sources = self.get_sources(code_unit, include_comments);
        if sources.is_empty() {
            None
        } else {
            Some(sources.into_iter().collect::<Vec<_>>().join("\n\n"))
        }
    }

    fn get_sources(&self, code_unit: &CodeUnit, include_comments: bool) -> BTreeSet<String> {
        if !include_comments {
            return self.inner.get_sources(code_unit, false);
        }

        let mut ranges = if code_unit.is_function() {
            let mut grouped = Vec::new();
            for candidate in self.inner.get_definitions(&code_unit.fq_name()) {
                if candidate.source() == code_unit.source() {
                    grouped.extend(self.inner.ranges_of(&candidate));
                }
            }
            grouped
        } else {
            self.inner.ranges_of(code_unit)
        };

        let Ok(source) = code_unit.source().read_to_string() else {
            return BTreeSet::new();
        };

        ranges.sort_by_key(|range| range.start_byte);
        ranges
            .into_iter()
            .filter_map(|range| {
                let start_byte = python_expanded_comment_start(&source, range.start_byte);
                source.get(start_byte..range.end_byte).map(str::to_string)
            })
            .collect()
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

    fn type_hierarchy_provider(&self) -> Option<&dyn TypeHierarchyProvider> {
        Some(self)
    }

    fn test_detection_provider(&self) -> Option<&dyn TestDetectionProvider> {
        Some(self)
    }

    fn contains_tests(&self, file: &ProjectFile) -> bool {
        self.inner.contains_tests(file)
    }
}

#[derive(Clone)]
struct Scope {
    kind: ScopeKind,
    path: String,
    code_unit: Option<CodeUnit>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ScopeKind {
    Class,
    Function,
}

struct PythonVisitor<'a> {
    file: &'a ProjectFile,
    source: &'a str,
    package_name: &'a str,
    parsed: &'a mut crate::analyzer::tree_sitter_analyzer::ParsedFile,
    module: Option<CodeUnit>,
}

impl<'a> PythonVisitor<'a> {
    fn visit_container(&mut self, node: Node<'_>, scope: &[Scope], module_control_depth: usize) {
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            self.visit_statement(child, scope, module_control_depth);
        }
    }

    fn visit_statement(&mut self, node: Node<'_>, scope: &[Scope], module_control_depth: usize) {
        match node.kind() {
            "decorated_definition" => {
                if let Some(definition) = node.child_by_field_name("definition") {
                    self.visit_definition(definition, Some(node), scope, module_control_depth);
                }
            }
            "class_definition" | "function_definition" => {
                self.visit_definition(node, None, scope, module_control_depth)
            }
            "expression_statement" => {
                self.visit_expression_statement(node, scope, module_control_depth)
            }
            "import_statement" | "import_from_statement" => self.visit_import_statement(node),
            "if_statement" | "try_statement" | "with_statement" | "for_statement"
            | "while_statement" => {
                let next_depth = if scope.is_empty() {
                    module_control_depth + 1
                } else {
                    module_control_depth
                };
                self.visit_container(node, scope, next_depth);
            }
            "elif_clause" | "else_clause" | "except_clause" | "finally_clause" => {
                self.visit_container(node, scope, module_control_depth);
            }
            "block" | "module" => self.visit_container(node, scope, module_control_depth),
            _ => {}
        }
    }

    fn visit_definition(
        &mut self,
        definition: Node<'_>,
        wrapper: Option<Node<'_>>,
        scope: &[Scope],
        module_control_depth: usize,
    ) {
        match definition.kind() {
            "class_definition" => self.visit_class_definition(
                definition,
                wrapper.unwrap_or(definition),
                scope,
                module_control_depth,
            ),
            "function_definition" => self.visit_function_definition(
                definition,
                wrapper.unwrap_or(definition),
                scope,
                module_control_depth,
            ),
            _ => {}
        }
    }

    fn visit_class_definition(
        &mut self,
        node: Node<'_>,
        range_node: Node<'_>,
        scope: &[Scope],
        module_control_depth: usize,
    ) {
        let Some(name_node) = node.child_by_field_name("name") else {
            return;
        };
        let name = py_node_text(name_node, self.source).trim();
        if name.is_empty() {
            return;
        }

        let capture = !scope.is_empty() || module_control_depth <= 1;

        let short_name = scope
            .last()
            .map(|parent| format!("{}${name}", parent.path))
            .unwrap_or_else(|| name.to_string());
        let code_unit = CodeUnit::new(
            self.file.clone(),
            CodeUnitType::Class,
            self.package_name.to_string(),
            short_name.clone(),
        );
        if capture {
            self.parsed
                .replace_code_unit(code_unit.clone(), range_node, self.source, None, None);
            self.parsed.add_signature(
                code_unit.clone(),
                python_class_signature(range_node, self.source),
            );
            if let Some(module) = &self.module
                && scope.is_empty()
            {
                self.parsed.add_child(module.clone(), code_unit.clone());
            }
            if let Some(parent) = scope.last()
                && let Some(parent_cu) = &parent.code_unit
            {
                self.parsed.add_child(parent_cu.clone(), code_unit.clone());
            }
            self.parsed.set_raw_supertypes(
                code_unit.clone(),
                extract_python_supertypes(node, self.source),
            );
        }

        let mut next_scope = scope.to_vec();
        if capture {
            next_scope.push(Scope {
                kind: ScopeKind::Class,
                path: short_name,
                code_unit: Some(code_unit),
            });
        }
        if let Some(body) = node.child_by_field_name("body") {
            self.visit_container(body, &next_scope, module_control_depth);
        }
    }

    fn visit_function_definition(
        &mut self,
        node: Node<'_>,
        range_node: Node<'_>,
        scope: &[Scope],
        module_control_depth: usize,
    ) {
        let Some(name_node) = node.child_by_field_name("name") else {
            return;
        };
        let name = py_node_text(name_node, self.source).trim();
        if name.is_empty() {
            return;
        }

        let capture = !python_is_property_mutator(range_node, self.source)
            && ((scope.is_empty() && module_control_depth <= 1)
                || scope
                    .last()
                    .is_some_and(|parent| parent.kind == ScopeKind::Class));
        let short_name = if let Some(parent) = scope.last() {
            match parent.kind {
                ScopeKind::Class => format!("{}.{}", parent.path, name),
                ScopeKind::Function => format!("{}${name}", parent.path),
            }
        } else {
            name.to_string()
        };

        if capture {
            let signature = node
                .child_by_field_name("parameters")
                .map(|parameters| py_node_text(parameters, self.source).trim().to_string());
            let code_unit = CodeUnit::with_signature(
                self.file.clone(),
                CodeUnitType::Function,
                self.package_name.to_string(),
                short_name.clone(),
                signature,
                false,
            );
            self.parsed
                .replace_code_unit(code_unit.clone(), range_node, self.source, None, None);
            self.parsed.add_signature(
                code_unit.clone(),
                python_function_signature(range_node, self.source),
            );
            if let Some(module) = &self.module
                && scope.is_empty()
            {
                self.parsed.add_child(module.clone(), code_unit.clone());
            }
            if let Some(parent) = scope.last()
                && parent.kind == ScopeKind::Class
                && let Some(parent_cu) = &parent.code_unit
            {
                self.parsed.add_child(parent_cu.clone(), code_unit.clone());
            }
            let scope_code_unit = Some(code_unit);
            let mut next_scope = scope.to_vec();
            next_scope.push(Scope {
                kind: ScopeKind::Function,
                path: short_name,
                code_unit: scope_code_unit,
            });
            if let Some(body) = node.child_by_field_name("body") {
                self.visit_container(body, &next_scope, module_control_depth);
            }
            return;
        }

        let mut next_scope = scope.to_vec();
        next_scope.push(Scope {
            kind: ScopeKind::Function,
            path: short_name,
            code_unit: None,
        });
        if let Some(body) = node.child_by_field_name("body") {
            self.visit_container(body, &next_scope, module_control_depth);
        }
    }

    fn visit_expression_statement(
        &mut self,
        node: Node<'_>,
        scope: &[Scope],
        module_control_depth: usize,
    ) {
        let Some(assignment) = node.named_child(0) else {
            return;
        };
        if assignment.kind() != "assignment" {
            return;
        }
        let Some(left) = assignment.child_by_field_name("left") else {
            return;
        };
        let names = collect_assigned_names(left, self.source);
        for name in names {
            let short_name = if let Some(parent) = scope.last() {
                if parent.kind != ScopeKind::Class {
                    continue;
                }
                format!("{}.{}", parent.path, name)
            } else if module_control_depth <= 1 {
                name.clone()
            } else {
                continue;
            };
            let code_unit = CodeUnit::new(
                self.file.clone(),
                CodeUnitType::Field,
                self.package_name.to_string(),
                short_name,
            );
            self.parsed
                .replace_code_unit(code_unit.clone(), node, self.source, None, None);
            self.parsed.add_signature(
                code_unit.clone(),
                py_node_text(node, self.source).trim().to_string(),
            );
            if let Some(module) = &self.module
                && scope.is_empty()
            {
                self.parsed.add_child(module.clone(), code_unit.clone());
            }
            if let Some(parent) = scope.last()
                && parent.kind == ScopeKind::Class
                && let Some(parent_cu) = &parent.code_unit
            {
                self.parsed.add_child(parent_cu.clone(), code_unit);
            }
        }
    }

    fn visit_import_statement(&mut self, node: Node<'_>) {
        let raw = py_node_text(node, self.source).trim();
        for info in parse_python_import_infos(raw) {
            self.parsed.import_statements.push(info.raw_snippet.clone());
            self.parsed.imports.push(info);
        }
    }
}

fn py_node_text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    source.get(node.start_byte()..node.end_byte()).unwrap_or("")
}

struct PythonModuleInfo {
    package_name: String,
    module_name: String,
}

impl PythonModuleInfo {
    fn module_qualified_package(&self) -> String {
        if self.package_name.is_empty() {
            self.module_name.clone()
        } else {
            format!("{}.{}", self.package_name, self.module_name)
        }
    }
}

fn python_module_name(file: &ProjectFile) -> String {
    python_module_info(file).module_qualified_package()
}

fn build_python_module_code_units(
    inner: &TreeSitterAnalyzer<PythonAdapter>,
) -> BTreeMap<String, CodeUnit> {
    inner
        .get_analyzed_files()
        .into_iter()
        .filter_map(|file| {
            let module_fq = python_module_name(&file);
            module_code_unit(&file, &module_fq).map(|code_unit| (module_fq, code_unit))
        })
        .collect()
}

fn python_module_info(file: &ProjectFile) -> PythonModuleInfo {
    let raw_package = python_package_name_for_file(file);
    let module_name = file
        .rel_path()
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or_default()
        .to_string();

    if module_name == "__init__" && !raw_package.is_empty() {
        if let Some((package_name, last_segment)) = raw_package.rsplit_once('.') {
            return PythonModuleInfo {
                package_name: package_name.to_string(),
                module_name: last_segment.to_string(),
            };
        }
        return PythonModuleInfo {
            package_name: String::new(),
            module_name: raw_package,
        };
    }

    PythonModuleInfo {
        package_name: raw_package,
        module_name,
    }
}

fn python_package_name_for_file(file: &ProjectFile) -> String {
    let Some(parent_rel) = file.rel_path().parent() else {
        return String::new();
    };
    if parent_rel.as_os_str().is_empty() {
        return String::new();
    }

    let mut effective_package_root_rel: Option<&Path> = None;
    let mut current_rel = Some(parent_rel);
    while let Some(path) = current_rel {
        if file.root().join(path).join("__init__.py").exists() {
            effective_package_root_rel = Some(path);
        }
        current_rel = path.parent();
    }

    let Some(package_root_rel) = effective_package_root_rel else {
        return dotted_path(parent_rel);
    };

    let Some(import_root_rel) = package_root_rel.parent() else {
        return dotted_path(parent_rel);
    };

    dotted_path(
        import_root_rel
            .strip_prefix("")
            .ok()
            .and_then(|_| parent_rel.strip_prefix(import_root_rel).ok())
            .unwrap_or(parent_rel),
    )
}

fn dotted_path(path: &Path) -> String {
    path.components()
        .map(|component| component.as_os_str().to_string_lossy().to_string())
        .filter(|component| !component.is_empty())
        .collect::<Vec<_>>()
        .join(".")
}

fn module_code_unit(file: &ProjectFile, module_fq: &str) -> Option<CodeUnit> {
    if module_fq.is_empty() {
        return None;
    }
    let mut parts = module_fq.rsplitn(2, '.');
    let short_name = parts.next().unwrap_or(module_fq);
    let package_name = parts.next().unwrap_or_default();
    Some(CodeUnit::new(
        file.clone(),
        CodeUnitType::Module,
        package_name.to_string(),
        short_name.to_string(),
    ))
}

fn python_class_signature(node: Node<'_>, source: &str) -> String {
    python_header_with_decorators(node, source)
}

fn python_function_signature(node: Node<'_>, source: &str) -> String {
    let header = python_header_with_decorators(node, source);
    if let Some((head, tail)) = header.rsplit_once('\n') {
        format!("{head}\n{} ...", tail.trim_end_matches(':'))
    } else {
        format!("{} ...", header.trim_end_matches(':'))
    }
}

fn python_is_property_mutator(node: Node<'_>, source: &str) -> bool {
    python_header_with_decorators(node, source)
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with('@'))
        .any(|decorator| decorator.ends_with(".setter") || decorator.ends_with(".deleter"))
}

fn python_expanded_comment_start(source: &str, start_byte: usize) -> usize {
    let line_starts = compute_line_starts(source);
    let line_index = find_line_index_for_offset(&line_starts, start_byte);

    let mut comment_start = start_byte;
    for line_idx in (0..line_index).rev() {
        let line_start = line_starts[line_idx];
        let line_end = line_starts
            .get(line_idx + 1)
            .copied()
            .unwrap_or(source.len());
        let line = &source[line_start..line_end];
        let trimmed = line.trim_start();

        if trimmed.trim().is_empty() {
            continue;
        }

        if trimmed.starts_with('#') {
            comment_start = line_start;
            continue;
        }

        break;
    }

    comment_start
}

fn python_header_with_decorators(node: Node<'_>, source: &str) -> String {
    let raw = py_node_text(node, source);
    let lines: Vec<_> = raw
        .lines()
        .map(str::trim_end)
        .filter(|line| !line.trim().is_empty())
        .collect();
    let mut relevant = Vec::new();
    for line in lines {
        let trimmed = line.trim_start();
        if trimmed.starts_with('@')
            || trimmed.starts_with("def ")
            || trimmed.starts_with("async def ")
            || trimmed.starts_with("class ")
        {
            relevant.push(trimmed.to_string());
            if trimmed.starts_with("def ")
                || trimmed.starts_with("async def ")
                || trimmed.starts_with("class ")
            {
                break;
            }
        }
    }
    relevant.join("\n")
}

fn extract_python_supertypes(node: Node<'_>, source: &str) -> Vec<String> {
    let Some(superclasses) = node.child_by_field_name("superclasses") else {
        return Vec::new();
    };
    let mut result = Vec::new();
    let mut cursor = superclasses.walk();
    for child in superclasses.named_children(&mut cursor) {
        match child.kind() {
            "identifier" | "attribute" => {
                let text = py_node_text(child, source).trim();
                if !text.is_empty() {
                    result.push(text.to_string());
                }
            }
            _ => {}
        }
    }
    result
}

fn collect_assigned_names(node: Node<'_>, source: &str) -> Vec<String> {
    let mut names = Vec::new();
    match node.kind() {
        "identifier" => {
            let text = py_node_text(node, source).trim();
            if !text.is_empty() {
                names.push(text.to_string());
            }
        }
        _ => {
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                names.extend(collect_assigned_names(child, source));
            }
        }
    }
    names
}

fn collect_python_identifiers(node: Node<'_>, source: &str, identifiers: &mut BTreeSet<String>) {
    if node.kind() == "identifier" {
        let text = py_node_text(node, source).trim();
        if !text.is_empty() {
            identifiers.insert(text.to_string());
        }
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        collect_python_identifiers(child, source, identifiers);
    }
}

fn python_source_contains_tests(source: &str) -> bool {
    static TEST_DEF_RE: std::sync::LazyLock<Regex> =
        std::sync::LazyLock::new(|| Regex::new(r"(?m)^\s*def\s+test_[A-Za-z0-9_]*\s*\(").unwrap());
    source.contains("@pytest.mark.") || TEST_DEF_RE.is_match(source)
}

fn extract_package_from_python_wildcard(raw: &str) -> Option<String> {
    let details = parse_python_import_details(raw)?;
    match details {
        PythonImportDetails::FromImport {
            module, wildcard, ..
        } if wildcard => Some(module),
        _ => None,
    }
}

#[derive(Debug, Clone)]
enum PythonImportDetails {
    Import {
        module: String,
        alias: Option<String>,
    },
    FromImport {
        module: String,
        name: String,
        alias: Option<String>,
        wildcard: bool,
    },
}

fn parse_python_import_infos(raw: &str) -> Vec<ImportInfo> {
    let mut infos = Vec::new();
    if let Some(body) = raw.strip_prefix("import ") {
        for part in split_top_level_commas(body) {
            let (module, alias) = split_alias(&part);
            infos.push(ImportInfo {
                raw_snippet: if let Some(alias) = &alias {
                    format!("import {module} as {alias}")
                } else {
                    format!("import {module}")
                },
                is_wildcard: false,
                identifier: Some(alias.clone().unwrap_or_else(|| {
                    module
                        .split('.')
                        .next_back()
                        .unwrap_or(module.as_str())
                        .to_string()
                })),
                alias,
            });
        }
    } else if let Some((module, names)) = raw
        .strip_prefix("from ")
        .and_then(|tail| tail.split_once(" import "))
    {
        if names.trim() == "*" {
            infos.push(ImportInfo {
                raw_snippet: format!("from {module} import *"),
                is_wildcard: true,
                identifier: None,
                alias: None,
            });
        } else {
            for part in split_top_level_commas(names) {
                let (name, alias) = split_alias(&part);
                infos.push(ImportInfo {
                    raw_snippet: if let Some(alias) = &alias {
                        format!("from {module} import {name} as {alias}")
                    } else {
                        format!("from {module} import {name}")
                    },
                    is_wildcard: false,
                    identifier: Some(alias.clone().unwrap_or_else(|| name.clone())),
                    alias,
                });
            }
        }
    }
    infos
}

fn parse_python_import_details(raw: &str) -> Option<PythonImportDetails> {
    if let Some(body) = raw.strip_prefix("import ") {
        let part = split_top_level_commas(body).into_iter().next()?;
        let (module, alias) = split_alias(&part);
        return Some(PythonImportDetails::Import { module, alias });
    }
    let (module, names) = raw.strip_prefix("from ")?.split_once(" import ")?;
    if names.trim() == "*" {
        return Some(PythonImportDetails::FromImport {
            module: module.to_string(),
            name: "*".to_string(),
            alias: None,
            wildcard: true,
        });
    }
    let part = split_top_level_commas(names).into_iter().next()?;
    let (name, alias) = split_alias(&part);
    Some(PythonImportDetails::FromImport {
        module: module.to_string(),
        name,
        alias,
        wildcard: false,
    })
}

fn split_top_level_commas(input: &str) -> Vec<String> {
    input
        .split(',')
        .map(normalize_python_import_part)
        .filter(|part| !part.is_empty())
        .collect()
}

fn normalize_python_import_part(input: &str) -> String {
    input
        .trim()
        .trim_start_matches('(')
        .trim_end_matches(')')
        .trim()
        .to_string()
}

fn split_alias(input: &str) -> (String, Option<String>) {
    input
        .rsplit_once(" as ")
        .map(|(name, alias)| (name.trim().to_string(), Some(alias.trim().to_string())))
        .unwrap_or_else(|| (input.trim().to_string(), None))
}

fn resolve_python_relative_module(source_file: &ProjectFile, module_expr: &str) -> Option<String> {
    let level = module_expr.chars().take_while(|ch| *ch == '.').count();
    let suffix = module_expr[level..].trim_matches('.');
    let current_package = python_current_package(source_file);
    let mut parts: Vec<_> = current_package
        .split('.')
        .filter(|part| !part.is_empty())
        .map(str::to_string)
        .collect();
    if level == 0 {
        return Some(module_expr.to_string());
    }
    if level > 0 {
        if level - 1 > parts.len() {
            return None;
        }
        parts.truncate(parts.len() - (level - 1));
    }
    if !suffix.is_empty() {
        parts.extend(suffix.split('.').map(str::to_string));
    }
    Some(parts.join("."))
}

fn python_current_package(source_file: &ProjectFile) -> String {
    let module = python_module_name(source_file);
    if source_file
        .rel_path()
        .file_name()
        .and_then(|name| name.to_str())
        == Some("__init__.py")
    {
        module
    } else {
        module
            .rsplit_once('.')
            .map(|(package, _)| package.to_string())
            .unwrap_or_default()
    }
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

fn weight_code_unit_vec(_key: &CodeUnit, value: &Arc<Vec<CodeUnit>>) -> u32 {
    let size = value
        .iter()
        .map(|item| item.fq_name().len() + size_of::<CodeUnit>())
        .sum::<usize>()
        + size_of::<Vec<CodeUnit>>();
    size.min(u32::MAX as usize) as u32
}

fn weight_code_unit_set_by_unit(_key: &CodeUnit, value: &Arc<BTreeSet<CodeUnit>>) -> u32 {
    let size = value
        .iter()
        .map(|item| item.fq_name().len() + size_of::<CodeUnit>())
        .sum::<usize>()
        + size_of::<BTreeSet<CodeUnit>>();
    size.min(u32::MAX as usize) as u32
}
