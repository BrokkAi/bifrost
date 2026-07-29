//! Kotlin analyzer: core parsing, declaration indexing, and persistence
//! (issue #1236).
//!
//! `KotlinAnalyzer` is a thin wrapper over the shared
//! [`TreeSitterAnalyzer`] engine: file enumeration, incremental updates,
//! persisted store round-trips, and every declaration-oriented query delegate
//! to the engine, with Kotlin-specific behavior isolated in
//! [`adapter::KotlinAdapter`] and [`declarations`].
//!
//! Capabilities owned by sibling issues stay explicitly unsupported here:
//! structured imports and type hierarchy (#1237), definition navigation
//! (#1238), usage graphs (#1239), structural RQL (#1240), and CFG/semantic
//! lowering (#1241 — the analyzer delegate hands out the shared
//! `UnsupportedProgramSemantics` provider instead of lowering).

mod adapter;
pub(crate) mod declarations;
pub(crate) mod language;

use crate::analyzer::{
    AnalyzerConfig, AnalyzerStoreContext, BuildProgress, CodeUnit, IAnalyzer, Language, Project,
    ProjectFile, SemanticDiagnostic, SignatureMetadata, TreeSitterAnalyzer, TypeAliasProvider,
    UsageFactsIndex,
};
use std::collections::BTreeSet;
use std::sync::Arc;

pub(crate) use adapter::KotlinAdapter;

#[derive(Clone)]
pub struct KotlinAnalyzer {
    inner: TreeSitterAnalyzer<KotlinAdapter>,
}

crate::analyzer::impl_forward_query_provider!(KotlinAnalyzer);

impl KotlinAnalyzer {
    pub fn new(project: Arc<dyn Project>) -> Self {
        Self::new_with_config(project, AnalyzerConfig::default())
    }

    pub fn new_with_config(project: Arc<dyn Project>, config: AnalyzerConfig) -> Self {
        Self {
            inner: TreeSitterAnalyzer::new_with_config(project, KotlinAdapter, config),
        }
    }

    pub fn from_project<P>(project: P) -> Self
    where
        P: Project + 'static,
    {
        Self::new(Arc::new(project))
    }

    pub(crate) fn new_with_config_store_context(
        project: Arc<dyn Project>,
        config: AnalyzerConfig,
        store_context: AnalyzerStoreContext,
        progress: Option<BuildProgress>,
    ) -> Result<Self, crate::analyzer::store::StoreError> {
        Ok(Self {
            inner: TreeSitterAnalyzer::new_with_config_storage_context_and_progress(
                project,
                KotlinAdapter,
                config,
                store_context,
                progress,
            )?,
        })
    }

    pub(crate) fn clone_with_project(&self, project: Arc<dyn Project>) -> Self {
        Self {
            inner: self.inner.clone_with_project(project),
        }
    }
}

impl TypeAliasProvider for KotlinAnalyzer {
    fn is_type_alias(&self, code_unit: &CodeUnit) -> bool {
        self.inner.is_type_alias(code_unit)
    }
}

impl IAnalyzer for KotlinAnalyzer {
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

    fn reset_workspace_path_scan_count_for_test(&self) {
        self.inner.reset_workspace_path_scan_count_for_test();
    }

    fn workspace_path_scan_count_for_test(&self) -> usize {
        self.inner.workspace_path_scan_count_for_test()
    }

    fn global_usage_definition_index(&self) -> &crate::analyzer::GlobalUsageDefinitionIndex {
        self.inner.global_usage_definition_index()
    }

    fn usage_facts_index(&self) -> &UsageFactsIndex {
        self.inner.usage_facts_index()
    }

    fn structural_search_providers(
        &self,
    ) -> Vec<&dyn crate::analyzer::structural::StructuralSearchProvider> {
        self.inner.structural_search_providers()
    }

    fn snapshot_caches(&self) -> Option<&crate::analyzer::AnalyzerSnapshotCaches> {
        Some(self.inner.snapshot_caches())
    }

    fn direct_children(&self, code_unit: &CodeUnit) -> Vec<CodeUnit> {
        self.inner
            .direct_children(code_unit)
            .into_iter()
            .filter(|child| !child.is_synthetic())
            .collect()
    }

    fn parent_of(&self, code_unit: &CodeUnit) -> Option<CodeUnit> {
        IAnalyzer::parent_of(&self.inner, code_unit)
    }

    fn import_statements(&self, file: &ProjectFile) -> Vec<String> {
        self.inner.import_statements(file)
    }

    fn ranges(&self, code_unit: &CodeUnit) -> Vec<crate::analyzer::Range> {
        self.inner.ranges(code_unit)
    }

    fn ranges_with_limit(
        &self,
        code_unit: &CodeUnit,
        max_ranges: usize,
        cancellation: &crate::CancellationToken,
    ) -> (Vec<crate::analyzer::Range>, usize, bool) {
        self.inner
            .ranges_with_limit(code_unit, max_ranges, cancellation)
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

    fn semantic_diagnostics(&self, file: &ProjectFile, source: &str) -> Vec<SemanticDiagnostic> {
        self.inner.semantic_diagnostics(file, source)
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

    fn type_alias_provider(&self) -> Option<&dyn TypeAliasProvider> {
        Some(self)
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
        let rendered = crate::analyzer::common::render_skeleton(self, code_unit, false);
        (!rendered.is_empty()).then(|| rendered.trim_end().to_string())
    }

    fn get_skeleton_header(&self, code_unit: &CodeUnit) -> Option<String> {
        let rendered = crate::analyzer::common::render_skeleton(self, code_unit, true);
        (!rendered.is_empty()).then(|| rendered.trim_end().to_string())
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

    fn lookup_candidates_by_identifier(&self, identifier: &str) -> BTreeSet<CodeUnit> {
        self.inner.lookup_declarations_by_identifier(identifier)
    }

    fn search_symbol_candidates(
        &self,
        patterns: &crate::analyzer::SearchSymbolPatternBatch,
        cancellation: Option<&crate::CancellationToken>,
    ) -> crate::analyzer::SearchSymbolCandidates {
        self.inner.search_symbol_candidates(patterns, cancellation)
    }

    fn contains_tests(&self, file: &ProjectFile) -> bool {
        self.inner.contains_tests(file)
    }

    fn in_test_region(&self, code_unit: &CodeUnit) -> bool {
        self.inner.in_test_region(code_unit)
    }
}
