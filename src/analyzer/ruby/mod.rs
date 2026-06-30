mod adapter;
mod cache;
mod declarations;
mod hierarchy;
mod imports;
mod mixins;
mod tests;

use crate::analyzer::js_ts::build_weighted_cache;
use crate::analyzer::type_relations::TypeRelation;
use crate::analyzer::{
    AnalyzerConfig, BuildProgress, CodeUnit, CodeUnitType, IAnalyzer, ImportAnalysisProvider,
    Language, Project, ProjectFile, SignatureMetadata, TestDetectionProvider, TreeSitterAnalyzer,
    TypeHierarchyProvider,
};
use crate::hash::{HashMap, HashSet};
use moka::sync::Cache;
use std::collections::BTreeSet;
use std::path::Path;
use std::sync::{Arc, OnceLock};

use adapter::RubyAdapter;
use cache::{
    weight_code_unit_set, weight_code_unit_set_by_unit, weight_code_unit_vec,
    weight_project_file_set,
};

pub(crate) use declarations::{
    RubyFieldScope, extract_name_path, extract_name_segments, parse_ruby_tree,
    ruby_field_short_name, ruby_variable_field_name,
};

#[derive(Clone)]
pub struct RubyAnalyzer {
    inner: TreeSitterAnalyzer<RubyAdapter>,
    memo_budget: u64,
    imported_code_units: Cache<ProjectFile, Arc<HashSet<CodeUnit>>>,
    referencing_files: Cache<ProjectFile, Arc<HashSet<ProjectFile>>>,
    direct_ancestors: Cache<CodeUnit, Arc<Vec<CodeUnit>>>,
    direct_descendants: Cache<CodeUnit, Arc<HashSet<CodeUnit>>>,
    direct_descendant_index: Arc<OnceLock<HashMap<String, Arc<HashSet<CodeUnit>>>>>,
    reverse_import_index: Arc<OnceLock<HashMap<ProjectFile, Arc<HashSet<ProjectFile>>>>>,
    zeitwerk_project: Arc<OnceLock<bool>>,
    zeitwerk_autoload_files: Arc<OnceLock<HashSet<ProjectFile>>>,
    zeitwerk_consumer_files: Arc<OnceLock<HashSet<ProjectFile>>>,
    zeitwerk_autoload_code_units: Arc<OnceLock<HashSet<CodeUnit>>>,
    zeitwerk_reference_files: Arc<OnceLock<HashMap<String, HashSet<ProjectFile>>>>,
    #[allow(dead_code)]
    mixin_relations: Arc<OnceLock<Vec<TypeRelation>>>,
    /// Class/module declarations indexed by their trailing identifier, for
    /// resolving relative (unqualified) supertype references without scanning
    /// every declaration.
    types_by_identifier: Arc<OnceLock<HashMap<String, Vec<CodeUnit>>>>,
}

impl RubyAnalyzer {
    pub fn new(project: Arc<dyn Project>) -> Self {
        Self::new_with_config(project, AnalyzerConfig::default())
    }

    pub fn new_with_config(project: Arc<dyn Project>, config: AnalyzerConfig) -> Self {
        let memo_budget = config.memo_cache_budget_bytes();
        let inner = TreeSitterAnalyzer::new_with_config(project, RubyAdapter, config);
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
                RubyAdapter,
                config,
                storage,
                move |event| progress(event),
            ),
            None => TreeSitterAnalyzer::new_with_config_and_storage(
                project,
                RubyAdapter,
                config,
                storage,
            ),
        };
        Self::from_inner(inner, memo_budget)
    }

    fn from_inner(inner: TreeSitterAnalyzer<RubyAdapter>, memo_budget: u64) -> Self {
        Self {
            inner,
            memo_budget,
            imported_code_units: build_weighted_cache(memo_budget / 4, weight_code_unit_set),
            referencing_files: build_weighted_cache(memo_budget / 8, weight_project_file_set),
            direct_ancestors: build_weighted_cache(memo_budget / 8, weight_code_unit_vec),
            direct_descendants: build_weighted_cache(memo_budget / 8, weight_code_unit_set_by_unit),
            direct_descendant_index: Arc::new(OnceLock::new()),
            reverse_import_index: Arc::new(OnceLock::new()),
            zeitwerk_project: Arc::new(OnceLock::new()),
            zeitwerk_autoload_files: Arc::new(OnceLock::new()),
            zeitwerk_consumer_files: Arc::new(OnceLock::new()),
            zeitwerk_autoload_code_units: Arc::new(OnceLock::new()),
            zeitwerk_reference_files: Arc::new(OnceLock::new()),
            mixin_relations: Arc::new(OnceLock::new()),
            types_by_identifier: Arc::new(OnceLock::new()),
        }
    }

    pub fn from_project<P>(project: P) -> Self
    where
        P: Project + 'static,
    {
        Self::new(Arc::new(project))
    }
}

impl IAnalyzer for RubyAnalyzer {
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

    fn signature_metadata<'a>(&'a self, code_unit: &CodeUnit) -> &'a [SignatureMetadata] {
        self.inner.signature_metadata(code_unit)
    }

    fn languages(&self) -> BTreeSet<Language> {
        self.inner.languages()
    }

    fn update(&self, changed_files: &BTreeSet<ProjectFile>) -> Self {
        Self::from_inner(self.inner.update(changed_files), self.memo_budget)
    }

    fn update_all(&self) -> Self {
        Self::from_inner(self.inner.update_all(), self.memo_budget)
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

    fn contains_tests(&self, file: &ProjectFile) -> bool {
        self.inner.contains_tests(file)
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
}
