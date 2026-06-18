mod adapter;
mod cache;
mod clones;
mod declarations;
mod hierarchy;
mod imports;
mod tests;
mod usage_index;

use crate::analyzer::clone_detection::{CloneCandidateProfile, detect_structural_clone_smells};
use crate::analyzer::common::language_for_file as file_language;
use crate::analyzer::js_ts::build_weighted_cache;
use crate::analyzer::usages::{
    ExportEntry, ExportIndex, ImportBinder, ImportBinding, ImportKind, ReexportStar,
};
use crate::analyzer::{
    AnalyzerConfig, CloneSmell, CloneSmellWeights, CodeUnit, CodeUnitType, IAnalyzer,
    ImportAnalysisProvider, Language, Project, ProjectFile, TestAssertionSmell,
    TestAssertionWeights, TestDetectionProvider, TreeSitterAnalyzer, TypeHierarchyProvider,
    build_reverse_import_index,
};
use crate::hash::{HashMap, HashSet};
use crate::profiling;
use moka::sync::Cache;
use std::collections::BTreeSet;
use std::sync::{Arc, OnceLock};

use adapter::PythonAdapter;
use cache::{
    weight_code_unit_set, weight_code_unit_set_by_unit, weight_code_unit_vec,
    weight_project_file_set,
};
use clones::{build_clone_candidate_data, refine_python_clone_similarity};
use declarations::{
    build_python_module_code_units, collect_python_identifiers, parse_python_tree,
    python_expanded_comment_start, python_module_name,
};
use imports::{PythonImportDetails, parse_python_import_details, resolve_python_relative_module};
use tests::detect_python_test_assertion_smells;
use usage_index::PythonUsageIndex;

#[derive(Clone)]
pub struct PythonAnalyzer {
    inner: TreeSitterAnalyzer<PythonAdapter>,
    memo_budget: u64,
    imported_code_units: Cache<ProjectFile, Arc<HashSet<CodeUnit>>>,
    referencing_files: Cache<ProjectFile, Arc<HashSet<ProjectFile>>>,
    direct_ancestors: Cache<CodeUnit, Arc<Vec<CodeUnit>>>,
    direct_descendants: Cache<CodeUnit, Arc<HashSet<CodeUnit>>>,
    module_code_units: Arc<HashMap<String, CodeUnit>>,
    reverse_import_index: Arc<OnceLock<HashMap<ProjectFile, Arc<HashSet<ProjectFile>>>>>,
    usage_index: Arc<OnceLock<PythonUsageIndex>>,
}

impl PythonAnalyzer {
    pub fn new(project: Arc<dyn Project>) -> Self {
        Self::new_with_config(project, AnalyzerConfig::default())
    }

    pub fn new_with_config(project: Arc<dyn Project>, config: AnalyzerConfig) -> Self {
        let memo_budget = config.memo_cache_budget_bytes();
        let inner = TreeSitterAnalyzer::new_with_config(project, PythonAdapter, config);
        Self::from_inner(inner, memo_budget)
    }

    pub fn new_with_config_and_storage(
        project: Arc<dyn Project>,
        config: AnalyzerConfig,
        storage: Arc<crate::analyzer::persistence::AnalyzerStorage>,
    ) -> Self {
        let memo_budget = config.memo_cache_budget_bytes();
        let inner = TreeSitterAnalyzer::new_with_config_and_storage(
            project,
            PythonAdapter,
            config,
            storage,
        );
        Self::from_inner(inner, memo_budget)
    }

    fn from_inner(inner: TreeSitterAnalyzer<PythonAdapter>, memo_budget: u64) -> Self {
        Self {
            module_code_units: Arc::new(build_python_module_code_units(&inner)),
            inner,
            memo_budget,
            imported_code_units: build_weighted_cache(memo_budget / 4, weight_code_unit_set),
            referencing_files: build_weighted_cache(memo_budget / 8, weight_project_file_set),
            direct_ancestors: build_weighted_cache(memo_budget / 8, weight_code_unit_vec),
            direct_descendants: build_weighted_cache(memo_budget / 8, weight_code_unit_set_by_unit),
            reverse_import_index: Arc::new(OnceLock::new()),
            usage_index: Arc::new(OnceLock::new()),
        }
    }

    pub fn from_project<P>(project: P) -> Self
    where
        P: Project + 'static,
    {
        Self::new(Arc::new(project))
    }

    fn extract_type_identifiers(&self, source: &str) -> BTreeSet<String> {
        let Some(tree) = parse_python_tree(source) else {
            return BTreeSet::new();
        };
        let mut identifiers = HashSet::default();
        collect_python_identifiers(tree.root_node(), source, &mut identifiers);
        identifiers.into_iter().collect()
    }

    fn resolve_module_code_unit(&self, module_fq: &str) -> Option<CodeUnit> {
        self.inner
            .definitions(module_fq)
            .find(|code_unit| code_unit.is_module())
            .cloned()
            .or_else(|| self.module_code_units.get(module_fq).cloned())
    }

    pub fn export_index_of(&self, file: &ProjectFile) -> ExportIndex {
        let mut index = ExportIndex::empty();

        for code_unit in self.inner.get_top_level_declarations(file) {
            let identifier = code_unit.identifier().trim();
            if identifier.is_empty() || identifier.starts_with('_') {
                continue;
            }
            index.exports_by_name.insert(
                identifier.to_string(),
                ExportEntry::Local {
                    local_name: identifier.to_string(),
                },
            );
        }

        for import in self.inner.import_info_of(file) {
            let Some(details) = parse_python_import_details(&import.raw_snippet) else {
                continue;
            };
            match details {
                PythonImportDetails::Import { .. } => {}
                PythonImportDetails::FromImport {
                    module,
                    name,
                    alias,
                    wildcard,
                } => {
                    let resolved_module = if module.starts_with('.') {
                        resolve_python_relative_module(file, &module)
                    } else {
                        Some(module.clone())
                    };
                    let Some(resolved_module) = resolved_module else {
                        continue;
                    };

                    if wildcard {
                        index.reexport_stars.push(ReexportStar {
                            module_specifier: resolved_module,
                        });
                        continue;
                    }

                    let exported_name = alias.unwrap_or(name.clone());
                    if exported_name.starts_with('_') {
                        continue;
                    }
                    let imported_name = format!("{resolved_module}.{name}");
                    if self.resolve_module_code_unit(&imported_name).is_some() {
                        index.exports_by_name.insert(
                            exported_name,
                            ExportEntry::ReexportedNamed {
                                module_specifier: imported_name,
                                imported_name: name,
                            },
                        );
                        continue;
                    }
                    index.exports_by_name.insert(
                        exported_name,
                        ExportEntry::ReexportedNamed {
                            module_specifier: resolved_module,
                            imported_name: name,
                        },
                    );
                }
            }
        }

        index
    }

    pub fn import_binder_of(&self, file: &ProjectFile) -> ImportBinder {
        let mut binder = ImportBinder::empty();

        for import in self.inner.import_info_of(file) {
            let Some(details) = parse_python_import_details(&import.raw_snippet) else {
                continue;
            };
            match details {
                PythonImportDetails::Import { module, alias } => {
                    let local_name = alias.unwrap_or_else(|| {
                        module
                            .split('.')
                            .next_back()
                            .unwrap_or(module.as_str())
                            .to_string()
                    });
                    binder.bindings.insert(
                        local_name,
                        ImportBinding {
                            module_specifier: module,
                            kind: ImportKind::Namespace,
                            imported_name: None,
                        },
                    );
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
                        Some(module.clone())
                    };
                    let Some(resolved_module) = resolved_module else {
                        continue;
                    };
                    if wildcard {
                        continue;
                    }
                    let local_name = alias.unwrap_or_else(|| name.clone());
                    let module_candidate = format!("{resolved_module}.{name}");
                    if self.resolve_module_code_unit(&module_candidate).is_some() {
                        binder.bindings.insert(
                            local_name,
                            ImportBinding {
                                module_specifier: module_candidate,
                                kind: ImportKind::Namespace,
                                imported_name: None,
                            },
                        );
                        continue;
                    }
                    binder.bindings.insert(
                        local_name,
                        ImportBinding {
                            module_specifier: resolved_module,
                            kind: ImportKind::Named,
                            imported_name: Some(name),
                        },
                    );
                }
            }
        }

        binder
    }

    fn build_reverse_import_index(&self) -> &HashMap<ProjectFile, Arc<HashSet<ProjectFile>>> {
        self.reverse_import_index.get_or_init(|| {
            let _scope = profiling::scope("PythonAnalyzer::build_reverse_import_index");
            let files: Vec<_> = self.inner.all_files().cloned().collect();
            let reverse =
                build_reverse_import_index(&files, |file| self.imported_code_units_of(file));

            if profiling::enabled() {
                profiling::note(format!(
                    "PythonAnalyzer::build_reverse_import_index files={} indexed_targets={}",
                    files.len(),
                    reverse.len()
                ));
            }

            reverse
        })
    }

    fn public_declarations_in_module(&self, module_fq: &str) -> Vec<CodeUnit> {
        let Some(module_code_unit) = self.resolve_module_code_unit(module_fq) else {
            return Vec::new();
        };
        self.inner
            .direct_children(&module_code_unit)
            .filter(|code_unit| !code_unit.identifier().starts_with('_'))
            .cloned()
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
                return self.inner.definitions(&fq_name).next().cloned();
            }
            return self.inner.definitions(trimmed).next().cloned();
        }

        if let Some(bound) = bindings.get(trimmed) {
            return Some(bound.clone());
        }

        let local_fq_name = format!("{}.{}", code_unit.package_name(), trimmed);
        self.inner
            .definitions(&local_fq_name)
            .next()
            .cloned()
            .or_else(|| self.inner.definitions(trimmed).next().cloned())
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

        let all_children: Vec<_> = self.inner.direct_children(code_unit).collect();
        let field_children: Vec<_> = all_children
            .iter()
            .copied()
            .filter(|child| child.is_field())
            .collect();
        let children = if header_only {
            field_children.clone()
        } else {
            all_children.clone()
        };
        if !children.is_empty() || code_unit.is_class() || code_unit.is_module() {
            let child_indent = format!("{indent}  ");
            for child in children {
                self.render_skeleton_recursive(child, &child_indent, header_only, out);
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
            CodeUnitType::Field | CodeUnitType::Macro => rendered.push_str(header.as_str()),
            CodeUnitType::Module => return None,
        }
        Some(rendered)
    }
}

impl IAnalyzer for PythonAnalyzer {
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

    fn definition_lookup_index(&self) -> &crate::analyzer::DefinitionLookupIndex {
        self.inner.definition_lookup_index()
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

    fn compute_cognitive_complexities(&self, file: &ProjectFile) -> Vec<(CodeUnit, u32)> {
        self.inner.compute_cognitive_complexities(file)
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
            usage_index: Arc::new(OnceLock::new()),
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
            usage_index: Arc::new(OnceLock::new()),
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

    fn parse_errors(&self, file: &ProjectFile) -> Option<Vec<crate::analyzer::ParseError>> {
        self.inner.parse_errors(file)
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
            for candidate in self.inner.definitions(&code_unit.fq_name()) {
                if candidate.source() == code_unit.source() {
                    grouped.extend(self.inner.ranges(candidate).iter().copied());
                }
            }
            grouped
        } else {
            self.inner.ranges(code_unit).to_vec()
        };

        let Ok(source) = self.inner.project().read_source(code_unit.source()) else {
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

    fn search_definitions_persisted(&self, pattern: &str) -> BTreeSet<CodeUnit> {
        self.inner.search_definitions_persisted(pattern)
    }

    fn signatures_of(&self, code_unit: &CodeUnit) -> Vec<String> {
        self.inner.signatures_of(code_unit).to_vec()
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

    fn find_test_assertion_smells(
        &self,
        file: &ProjectFile,
        weights: TestAssertionWeights,
    ) -> Vec<TestAssertionSmell> {
        if !self.contains_tests(file) || file_language(file) != Language::Python {
            return Vec::new();
        }
        let Ok(source) = self.inner.project().read_source(file) else {
            return Vec::new();
        };
        detect_python_test_assertion_smells(file, &source, &weights)
    }

    fn find_structural_clone_smells(
        &self,
        file: &ProjectFile,
        weights: CloneSmellWeights,
    ) -> Vec<CloneSmell> {
        self.find_structural_clone_smells_for_files(std::slice::from_ref(file), weights)
    }

    fn find_structural_clone_smells_for_files(
        &self,
        files: &[ProjectFile],
        weights: CloneSmellWeights,
    ) -> Vec<CloneSmell> {
        let requested_files: Vec<ProjectFile> = files
            .iter()
            .filter(|file| file_language(file) == Language::Python)
            .cloned()
            .collect();
        if requested_files.is_empty() {
            return Vec::new();
        }

        let all_candidates: Vec<CloneCandidateProfile> = self
            .get_all_declarations()
            .into_iter()
            .filter(|code_unit| {
                code_unit.is_function() && file_language(code_unit.source()) == Language::Python
            })
            .filter_map(|code_unit| build_clone_candidate_data(self, &code_unit, weights))
            .map(|candidate| CloneCandidateProfile::create(candidate, weights))
            .collect();
        if all_candidates.is_empty() {
            return Vec::new();
        }

        detect_structural_clone_smells(
            &requested_files,
            all_candidates,
            weights,
            refine_python_clone_similarity,
        )
    }
}
