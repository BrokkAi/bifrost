mod adapter;
mod cache;
mod cargo_routes;
mod declarations;
mod diagnostics;
pub(crate) mod field_roles;
mod graph_support;
mod hierarchy;
mod imports;
pub(crate) mod lexical_scope;
mod semantic;
pub(crate) mod structural;
mod tests;
mod usage_index;

use crate::analyzer::common::language_for_file as file_language;
use crate::analyzer::type_relations::TypeRelation;
use crate::analyzer::{
    AnalyzerConfig, AnalyzerStoreContext, BuildProgress, CodeUnit, IAnalyzer,
    ImportAnalysisProvider, Language, PoolSafeMemo, Project, ProjectFile, SemanticDiagnostic,
    SignatureMetadata, TestAssertionSmell, TestAssertionWeights, TestDetectionProvider,
    TreeSitterAnalyzer, TypeAliasProvider, TypeHierarchyProvider,
};
use crate::hash::{HashMap, HashSet};
use moka::sync::Cache;
use std::collections::BTreeSet;
use std::sync::{Arc, OnceLock};
use tree_sitter::Parser;

use super::js_ts::build_weighted_cache;
pub(crate) use adapter::RustAdapter;
use cache::{
    weight_code_unit_set, weight_export_index, weight_project_file_set, weight_reference_context,
};
use cargo_routes::RustCargoRouteIndex;
use declarations::collect_rust_type_identifiers;
pub(crate) use field_roles::rust_is_field_declaration_name;
pub(crate) use imports::rust_focused_use_path;
use tests::detect_rust_test_assertion_smells;

pub use graph_support::RustReferenceContext;
use hierarchy::RustHierarchyIndex;
pub(crate) use usage_index::RustBindingSeeds;
use usage_index::RustUsageIndex;

#[derive(Clone)]
pub struct RustAnalyzer {
    inner: TreeSitterAnalyzer<RustAdapter>,
    memo_budget: u64,
    imported_code_units: Cache<ProjectFile, Arc<HashSet<CodeUnit>>>,
    referencing_files: Cache<ProjectFile, Arc<HashSet<ProjectFile>>>,
    reference_contexts: Cache<ProjectFile, Arc<RustReferenceContext>>,
    forward_reference_contexts: Cache<ProjectFile, Arc<RustReferenceContext>>,
    export_indexes: Cache<ProjectFile, Arc<crate::analyzer::usages::ExportIndex>>,
    reverse_import_index: Arc<PoolSafeMemo<HashMap<ProjectFile, Arc<HashSet<ProjectFile>>>>>,
    cargo_routes: Arc<OnceLock<Arc<RustCargoRouteIndex>>>,
    usage_index: Arc<OnceLock<RustUsageIndex>>,
    hierarchy_index: Arc<OnceLock<RustHierarchyIndex>>,
    #[allow(dead_code)]
    type_relations: Arc<OnceLock<Vec<TypeRelation>>>,
}

crate::analyzer::impl_forward_query_provider!(RustAnalyzer);

impl RustAnalyzer {
    pub(crate) fn prepared_syntax(
        &self,
        file: &ProjectFile,
    ) -> Option<Arc<crate::analyzer::tree_sitter_analyzer::PreparedSyntaxTree>> {
        self.inner.prepared_syntax(file)
    }

    #[cfg(test)]
    pub(crate) fn prepared_syntax_parse_count_for_test(&self, file: &ProjectFile) -> usize {
        self.inner.prepared_syntax_parse_count_for_test(file)
    }

    fn indexed_sources_unchanged(&self, changed_files: &BTreeSet<ProjectFile>) -> bool {
        changed_files
            .iter()
            .filter(|file| file_language(file) == Language::Rust || self.inner.is_analyzed(file))
            .all(|file| {
                self.inner
                    .project()
                    .read_source(file)
                    .ok()
                    .is_some_and(|source| self.inner.indexed_source_matches(file, &source))
            })
    }

    pub(crate) fn clone_with_project(&self, project: Arc<dyn Project>) -> Self {
        let mut clone = self.clone();
        clone.inner = clone.inner.clone_with_project(project);
        clone.cargo_routes = Arc::new(OnceLock::new());
        clone
    }

    /// Explicit inverse-analysis support. Forward definition and type queries
    /// resolve only the importing file's manifest route.
    fn cargo_routes(&self) -> Arc<RustCargoRouteIndex> {
        self.cargo_routes
            .get_or_init(|| {
                let files: Vec<_> = self.get_analyzed_files().into_iter().collect();
                Arc::new(RustCargoRouteIndex::build(&files))
            })
            .clone()
    }

    pub fn new(project: Arc<dyn Project>) -> Self {
        Self::new_with_config(project, AnalyzerConfig::default())
    }

    pub fn new_with_config(project: Arc<dyn Project>, config: AnalyzerConfig) -> Self {
        let memo_budget = config.memo_cache_budget_bytes();
        Self {
            inner: TreeSitterAnalyzer::new_with_config(project, RustAdapter, config),
            memo_budget,
            imported_code_units: build_weighted_cache(memo_budget / 4, weight_code_unit_set),
            referencing_files: build_weighted_cache(memo_budget / 8, weight_project_file_set),
            reference_contexts: build_weighted_cache(memo_budget / 8, weight_reference_context),
            forward_reference_contexts: build_weighted_cache(
                memo_budget / 8,
                weight_reference_context,
            ),
            export_indexes: build_weighted_cache(memo_budget / 8, weight_export_index),
            reverse_import_index: Arc::new(PoolSafeMemo::new()),
            cargo_routes: Arc::new(OnceLock::new()),
            usage_index: Arc::new(OnceLock::new()),
            hierarchy_index: Arc::new(OnceLock::new()),
            type_relations: Arc::new(OnceLock::new()),
        }
    }

    pub(crate) fn new_with_config_store_context(
        project: Arc<dyn Project>,
        config: AnalyzerConfig,
        store_context: AnalyzerStoreContext,
        progress: Option<BuildProgress>,
    ) -> Result<Self, crate::analyzer::store::StoreError> {
        let memo_budget = config.memo_cache_budget_bytes();
        let inner = TreeSitterAnalyzer::new_with_config_storage_context_and_progress(
            project,
            RustAdapter,
            config,
            store_context,
            progress,
        )?;
        Ok(Self {
            inner,
            memo_budget,
            imported_code_units: build_weighted_cache(memo_budget / 4, weight_code_unit_set),
            referencing_files: build_weighted_cache(memo_budget / 8, weight_project_file_set),
            reference_contexts: build_weighted_cache(memo_budget / 8, weight_reference_context),
            forward_reference_contexts: build_weighted_cache(
                memo_budget / 8,
                weight_reference_context,
            ),
            export_indexes: build_weighted_cache(memo_budget / 8, weight_export_index),
            reverse_import_index: Arc::new(PoolSafeMemo::new()),
            cargo_routes: Arc::new(OnceLock::new()),
            usage_index: Arc::new(OnceLock::new()),
            hierarchy_index: Arc::new(OnceLock::new()),
            type_relations: Arc::new(OnceLock::new()),
        })
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
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("failed to load rust parser");
        let Some(tree) = parser.parse(source, None) else {
            return BTreeSet::new();
        };
        let mut identifiers = HashSet::default();
        collect_rust_type_identifiers(tree.root_node(), source, &mut identifiers);
        identifiers.into_iter().collect()
    }
}

impl TypeAliasProvider for RustAnalyzer {
    fn is_type_alias(&self, code_unit: &CodeUnit) -> bool {
        self.inner.is_type_alias(code_unit)
    }
}

impl TestDetectionProvider for RustAnalyzer {}

impl IAnalyzer for RustAnalyzer {
    fn begin_query(&self, context: &Arc<crate::analyzer::AnalyzerQueryContext>) {
        self.inner.begin_query(context);
    }

    fn end_query(&self, context: &Arc<crate::analyzer::AnalyzerQueryContext>) {
        self.inner.end_query(context);
    }

    fn top_level_declarations(&self, file: &ProjectFile) -> Vec<CodeUnit> {
        self.inner.top_level_declarations(file)
    }

    fn summary_file_projection(
        &self,
        file: &ProjectFile,
    ) -> Option<Arc<crate::analyzer::SummaryFileProjection>> {
        self.inner.summary_file_projection(file)
    }

    fn analyzed_files(&self) -> Vec<ProjectFile> {
        self.inner.analyzed_files()
    }

    fn indexed_source(&self, file: &ProjectFile) -> Option<String> {
        self.inner.indexed_source(file)
    }

    fn indexed_source_matches(&self, file: &ProjectFile, source: &str) -> bool {
        self.inner.indexed_source_matches(file, source)
    }

    fn is_analyzed(&self, file: &ProjectFile) -> bool {
        self.inner.is_analyzed(file)
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

    fn global_usage_definition_index(&self) -> &crate::analyzer::GlobalUsageDefinitionIndex {
        self.inner.global_usage_definition_index()
    }

    fn reset_global_usage_definition_index_build_count_for_test(&self) {
        self.inner
            .reset_global_usage_definition_index_build_count_for_test();
    }

    fn global_usage_definition_index_build_count_for_test(&self) -> usize {
        self.inner
            .global_usage_definition_index_build_count_for_test()
    }

    fn reset_full_declaration_scan_count_for_test(&self) {
        self.inner.reset_full_declaration_scan_count_for_test();
    }

    fn full_declaration_scan_count_for_test(&self) -> usize {
        self.inner.full_declaration_scan_count_for_test()
    }

    fn reset_candidate_hydration_count_for_test(&self) {
        self.inner.reset_full_hydration_count_for_test();
    }

    fn candidate_hydration_count_for_test(&self) -> usize {
        self.inner.full_hydration_count_for_test() + self.inner.bulk_hydration_count_for_test()
    }

    fn full_candidate_hydration_count_for_test(&self) -> usize {
        self.inner.full_hydration_count_for_test()
    }

    fn bulk_candidate_hydration_count_for_test(&self) -> usize {
        self.inner.bulk_hydration_count_for_test()
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

    fn get_analyzed_files(&self) -> BTreeSet<ProjectFile> {
        self.inner.get_analyzed_files()
    }

    fn languages(&self) -> BTreeSet<Language> {
        self.inner.languages()
    }

    fn update(&self, changed_files: &BTreeSet<ProjectFile>) -> Self {
        if self.indexed_sources_unchanged(changed_files) {
            return self.clone();
        }

        Self {
            inner: self.inner.update(changed_files),
            memo_budget: self.memo_budget,
            imported_code_units: build_weighted_cache(self.memo_budget / 4, weight_code_unit_set),
            referencing_files: build_weighted_cache(self.memo_budget / 8, weight_project_file_set),
            reference_contexts: build_weighted_cache(
                self.memo_budget / 8,
                weight_reference_context,
            ),
            forward_reference_contexts: build_weighted_cache(
                self.memo_budget / 8,
                weight_reference_context,
            ),
            export_indexes: build_weighted_cache(self.memo_budget / 8, weight_export_index),
            reverse_import_index: Arc::new(PoolSafeMemo::new()),
            cargo_routes: Arc::new(OnceLock::new()),
            usage_index: Arc::new(OnceLock::new()),
            hierarchy_index: Arc::new(OnceLock::new()),
            type_relations: Arc::new(OnceLock::new()),
        }
    }

    fn update_all(&self) -> Self {
        Self {
            inner: self.inner.update_all(),
            memo_budget: self.memo_budget,
            imported_code_units: build_weighted_cache(self.memo_budget / 4, weight_code_unit_set),
            referencing_files: build_weighted_cache(self.memo_budget / 8, weight_project_file_set),
            reference_contexts: build_weighted_cache(
                self.memo_budget / 8,
                weight_reference_context,
            ),
            forward_reference_contexts: build_weighted_cache(
                self.memo_budget / 8,
                weight_reference_context,
            ),
            export_indexes: build_weighted_cache(self.memo_budget / 8, weight_export_index),
            reverse_import_index: Arc::new(PoolSafeMemo::new()),
            cargo_routes: Arc::new(OnceLock::new()),
            usage_index: Arc::new(OnceLock::new()),
            hierarchy_index: Arc::new(OnceLock::new()),
            type_relations: Arc::new(OnceLock::new()),
        }
    }

    fn project(&self) -> &dyn Project {
        self.inner.project()
    }

    fn get_all_declarations(&self) -> Vec<CodeUnit> {
        self.inner.get_all_declarations()
    }

    fn get_definitions(&self, fq_name: &str) -> Vec<CodeUnit> {
        self.inner.get_definitions(fq_name)
    }

    fn parse_errors(&self, file: &ProjectFile) -> Option<Vec<crate::analyzer::ParseError>> {
        self.inner.parse_errors(file)
    }

    fn semantic_diagnostics(&self, file: &ProjectFile, source: &str) -> Vec<SemanticDiagnostic> {
        diagnostics::collect_rust_semantic_diagnostics(self, file, source)
            .into_iter()
            .map(Into::into)
            .collect()
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

    fn lookup_candidates_by_short_name(&self, symbol: &str) -> BTreeSet<CodeUnit> {
        self.inner.lookup_candidates_by_short_name(symbol)
    }

    fn search_symbol_candidates(
        &self,
        pattern: &str,
        auto_quote: bool,
    ) -> Vec<crate::analyzer::SearchSymbolCandidate> {
        self.inner.search_symbol_candidates(pattern, auto_quote)
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
        if !self.contains_tests(file) || file_language(file) != Language::Rust {
            return Vec::new();
        }
        let Ok(source) = self.inner.project().read_source(file) else {
            return Vec::new();
        };
        detect_rust_test_assertion_smells(file, &source, &weights)
    }
}
