mod adapter;
mod cache;
mod clones;
mod declarations;
mod hierarchy;
mod imports;
mod structural;
mod tests;

use crate::analyzer::clone_detection::{CloneCandidateProfile, detect_structural_clone_smells};
use crate::analyzer::common::language_for_file as file_language;
use crate::analyzer::js_ts::{
    build_weighted_cache, weight_code_unit_set_by_unit, weight_code_unit_vec_by_unit,
};
use crate::analyzer::{
    AnalyzerConfig, BuildProgress, CloneSmell, CloneSmellWeights, CodeUnit, CodeUnitType,
    IAnalyzer, ImportAnalysisProvider, ImportInfo, Language, PoolSafeMemo, Project, ProjectFile,
    SignatureMetadata, TestAssertionSmell, TestAssertionWeights, TestDetectionProvider,
    TreeSitterAnalyzer, TypeAliasProvider, TypeHierarchyProvider,
};
use crate::hash::{HashMap, HashSet};
use moka::sync::Cache;
use regex::Regex;
use std::collections::BTreeSet;
use std::sync::{Arc, OnceLock};

use adapter::CppAdapter;
use cache::{weight_code_unit_set_by_file, weight_project_file_set};
use clones::{build_clone_candidate_data, refine_cpp_clone_similarity};
use tests::detect_cpp_test_assertion_smells;

pub(crate) use declarations::{node_text, normalize_cpp_whitespace};
pub(crate) use imports::{
    IncludeTargetIndex, include_paths, resolve_include_targets, resolve_include_targets_with_index,
};
#[derive(Clone)]
pub struct CppAnalyzer {
    inner: TreeSitterAnalyzer<CppAdapter>,
    memo_budget: u64,
    imported_code_units: Cache<ProjectFile, Arc<HashSet<CodeUnit>>>,
    referencing_files: Cache<ProjectFile, Arc<HashSet<ProjectFile>>>,
    direct_ancestors: Cache<CodeUnit, Arc<Vec<CodeUnit>>>,
    direct_descendants: Cache<CodeUnit, Arc<HashSet<CodeUnit>>>,
    include_target_index: Arc<OnceLock<IncludeTargetIndex>>,
    reverse_include_index: Arc<PoolSafeMemo<HashMap<ProjectFile, Arc<HashSet<ProjectFile>>>>>,
    direct_ancestor_index: Arc<OnceLock<HashMap<String, Arc<Vec<CodeUnit>>>>>,
    direct_descendant_index: Arc<OnceLock<HashMap<String, Arc<HashSet<CodeUnit>>>>>,
}

impl CppAnalyzer {
    pub fn new(project: Arc<dyn Project>) -> Self {
        Self::new_with_config(project, AnalyzerConfig::default())
    }

    pub fn new_with_config(project: Arc<dyn Project>, config: AnalyzerConfig) -> Self {
        let memo_budget = config.memo_cache_budget_bytes();
        let inner = TreeSitterAnalyzer::new_with_config(project, CppAdapter, config);
        Self::from_inner(inner, memo_budget)
    }

    pub fn new_with_config_and_storage(
        project: Arc<dyn Project>,
        config: AnalyzerConfig,
        storage: Arc<crate::analyzer::persistence::AnalyzerStorage>,
    ) -> Self {
        Self::new_with_config_storage(project, config, storage, None)
    }

    pub(crate) fn new_with_config_storage_and_progress(
        project: Arc<dyn Project>,
        config: AnalyzerConfig,
        storage: Arc<crate::analyzer::persistence::AnalyzerStorage>,
        progress: BuildProgress,
    ) -> Self {
        Self::new_with_config_storage(project, config, storage, Some(progress))
    }

    fn new_with_config_storage(
        project: Arc<dyn Project>,
        config: AnalyzerConfig,
        storage: Arc<crate::analyzer::persistence::AnalyzerStorage>,
        progress: Option<BuildProgress>,
    ) -> Self {
        let memo_budget = config.memo_cache_budget_bytes();
        let inner = match progress {
            Some(progress) => TreeSitterAnalyzer::new_with_config_storage_and_progress(
                project,
                CppAdapter,
                config,
                storage,
                move |event| progress(event),
            ),
            None => TreeSitterAnalyzer::new_with_config_and_storage(
                project, CppAdapter, config, storage,
            ),
        };
        Self::from_inner(inner, memo_budget)
    }

    fn from_inner(inner: TreeSitterAnalyzer<CppAdapter>, memo_budget: u64) -> Self {
        Self {
            inner,
            memo_budget,
            imported_code_units: build_weighted_cache(
                memo_budget / 4,
                weight_code_unit_set_by_file,
            ),
            referencing_files: build_weighted_cache(memo_budget / 8, weight_project_file_set),
            direct_ancestors: build_weighted_cache(memo_budget / 8, weight_code_unit_vec_by_unit),
            direct_descendants: build_weighted_cache(memo_budget / 8, weight_code_unit_set_by_unit),
            include_target_index: Arc::new(OnceLock::new()),
            reverse_include_index: Arc::new(PoolSafeMemo::new()),
            direct_ancestor_index: Arc::new(OnceLock::new()),
            direct_descendant_index: Arc::new(OnceLock::new()),
        }
    }

    fn with_updated_inner(&self, inner: TreeSitterAnalyzer<CppAdapter>) -> Self {
        Self {
            inner,
            memo_budget: self.memo_budget,
            imported_code_units: self.imported_code_units.clone(),
            referencing_files: self.referencing_files.clone(),
            direct_ancestors: build_weighted_cache(
                self.memo_budget / 8,
                weight_code_unit_vec_by_unit,
            ),
            direct_descendants: build_weighted_cache(
                self.memo_budget / 8,
                weight_code_unit_set_by_unit,
            ),
            include_target_index: Arc::new(OnceLock::new()),
            reverse_include_index: Arc::new(PoolSafeMemo::new()),
            direct_ancestor_index: Arc::new(OnceLock::new()),
            direct_descendant_index: Arc::new(OnceLock::new()),
        }
    }

    pub fn from_project<P>(project: P) -> Self
    where
        P: Project + 'static,
    {
        Self::new(Arc::new(project))
    }
}

impl CppAnalyzer {
    pub fn extract_type_identifiers(&self, source: &str) -> BTreeSet<String> {
        static IDENT_RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
        let regex =
            IDENT_RE.get_or_init(|| Regex::new(r"[A-Za-z_][A-Za-z0-9_:<>]*").expect("valid regex"));
        regex
            .find_iter(source)
            .map(|m| m.as_str())
            .filter(|token| {
                token
                    .chars()
                    .next()
                    .is_some_and(|ch| ch.is_ascii_uppercase())
            })
            .map(|token| token.trim_matches(':').to_string())
            .collect()
    }

    pub(crate) fn definition_lookup_index_shared(
        &self,
    ) -> Arc<crate::analyzer::DefinitionLookupIndex> {
        self.inner.definition_lookup_index_shared()
    }
}

impl IAnalyzer for CppAnalyzer {
    fn top_level_declarations(&self, file: &ProjectFile) -> Vec<CodeUnit> {
        self.inner.top_level_declarations(file)
    }

    fn analyzed_files(&self) -> Vec<ProjectFile> {
        self.inner.analyzed_files()
    }

    fn is_analyzed(&self, file: &ProjectFile) -> bool {
        self.inner.is_analyzed(file)
    }

    fn indexed_source<'a>(&'a self, file: &ProjectFile) -> Option<&'a str> {
        self.inner.indexed_source(file)
    }

    fn all_declarations(&self) -> Box<dyn Iterator<Item = CodeUnit> + '_> {
        self.inner.all_declarations()
    }

    fn declarations(&self, file: &ProjectFile) -> BTreeSet<CodeUnit> {
        self.inner.declarations(file)
    }

    fn definitions(&self, fq_name: &str) -> Box<dyn Iterator<Item = CodeUnit> + '_> {
        self.inner.definitions(fq_name)
    }

    fn definition_lookup_index(&self) -> &crate::analyzer::DefinitionLookupIndex {
        self.inner.definition_lookup_index()
    }

    fn direct_children(&self, code_unit: &CodeUnit) -> Vec<CodeUnit> {
        self.inner.direct_children(code_unit)
    }

    fn import_statements(&self, file: &ProjectFile) -> Vec<String> {
        self.inner.import_statements(file)
    }

    fn ranges(&self, code_unit: &CodeUnit) -> Vec<crate::analyzer::Range> {
        self.inner.ranges(code_unit)
    }

    fn compute_cognitive_complexities(&self, file: &ProjectFile) -> Vec<(CodeUnit, u32)> {
        self.inner.compute_cognitive_complexities(file)
    }

    fn signatures(&self, code_unit: &CodeUnit) -> Vec<String> {
        self.inner.signatures(code_unit)
    }

    fn signature_metadata(&self, code_unit: &CodeUnit) -> Vec<SignatureMetadata> {
        self.inner.signature_metadata(code_unit)
    }

    fn languages(&self) -> BTreeSet<Language> {
        self.inner.languages()
    }

    fn update(&self, changed_files: &BTreeSet<ProjectFile>) -> Self {
        self.with_updated_inner(self.inner.update(changed_files))
    }

    fn update_all(&self) -> Self {
        self.with_updated_inner(self.inner.update_all())
    }

    fn project(&self) -> &dyn Project {
        self.inner.project()
    }

    fn parse_errors(&self, file: &ProjectFile) -> Option<Vec<crate::analyzer::ParseError>> {
        self.inner.parse_errors(file)
    }

    fn extract_call_receiver(&self, reference: &str) -> Option<String> {
        self.inner.extract_call_receiver(reference)
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

    fn search_definitions_persisted(&self, pattern: &str) -> BTreeSet<CodeUnit> {
        self.inner.search_definitions_persisted(pattern)
    }

    fn import_analysis_provider(&self) -> Option<&dyn ImportAnalysisProvider> {
        Some(self)
    }

    fn type_alias_provider(&self) -> Option<&dyn TypeAliasProvider> {
        Some(self)
    }

    fn type_hierarchy_provider(&self) -> Option<&dyn TypeHierarchyProvider> {
        Some(self)
    }

    fn structural_search_providers(
        &self,
    ) -> Vec<&dyn crate::analyzer::structural::StructuralSearchProvider> {
        self.inner.structural_search_providers()
    }

    fn contains_tests(&self, file: &ProjectFile) -> bool {
        self.inner.contains_tests(file)
    }

    fn find_test_assertion_smells(
        &self,
        file: &ProjectFile,
        weights: TestAssertionWeights,
    ) -> Vec<TestAssertionSmell> {
        if !self.contains_tests(file) || file_language(file) != Language::Cpp {
            return Vec::new();
        }
        let Ok(source) = self.inner.project().read_source(file) else {
            return Vec::new();
        };
        detect_cpp_test_assertion_smells(file, &source, &weights)
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
            .filter(|file| file_language(file) == Language::Cpp)
            .cloned()
            .collect();
        if requested_files.is_empty() {
            return Vec::new();
        }

        let all_candidates: Vec<CloneCandidateProfile> = self
            .get_all_declarations()
            .into_iter()
            .filter(|code_unit| {
                code_unit.is_function() && file_language(code_unit.source()) == Language::Cpp
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
            refine_cpp_clone_similarity,
        )
    }

    fn test_detection_provider(&self) -> Option<&dyn TestDetectionProvider> {
        Some(self)
    }
}

impl TypeAliasProvider for CppAnalyzer {
    fn is_type_alias(&self, code_unit: &CodeUnit) -> bool {
        self.inner.is_type_alias(code_unit)
    }
}
