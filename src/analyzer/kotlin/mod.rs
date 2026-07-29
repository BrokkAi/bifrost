//! Kotlin analyzer: core parsing, declaration indexing, and persistence
//! (issue #1236).
//!
//! `KotlinAnalyzer` is a thin wrapper over the shared
//! [`TreeSitterAnalyzer`] engine: file enumeration, incremental updates,
//! persisted store round-trips, and every declaration-oriented query delegate
//! to the engine, with Kotlin-specific behavior isolated in
//! [`adapter::KotlinAdapter`] and [`declarations`].
//!
//! Name resolution — structured imports, supertypes, and the shared JVM
//! dependency realm — lands in [`imports`] (issue #1237).
//!
//! Capabilities owned by sibling issues stay explicitly unsupported here:
//! definition navigation (#1238), usage graphs (#1239), structural RQL
//! (#1240), and CFG/semantic lowering (#1241 — the analyzer delegate hands out
//! the shared `UnsupportedProgramSemantics` provider instead of lowering).

mod adapter;
pub(crate) mod declarations;
pub(crate) mod imports;
pub(crate) mod language;

use crate::analyzer::js_ts::cache::{
    build_weighted_cache, weight_code_unit_set, weight_project_file_set,
};
use crate::analyzer::jvm::dependency_discovery::is_jvm_dependency_input;
use crate::analyzer::jvm::external::JvmExternalDeclarationIndex;
use crate::analyzer::pool_memo::PoolSafeMemo;
use crate::analyzer::{
    AnalyzerConfig, AnalyzerStoreContext, BuildProgress, CodeUnit, IAnalyzer, JvmAnalyzerConfig,
    Language, Project, ProjectFile, SemanticDiagnostic, SignatureMetadata, TreeSitterAnalyzer,
    TypeAliasProvider, UsageFactsIndex,
};
use crate::hash::{HashMap, HashSet};
use moka::sync::Cache;
use std::collections::BTreeSet;
use std::sync::{Arc, OnceLock};

pub(crate) use adapter::KotlinAdapter;

#[derive(Clone)]
pub struct KotlinAnalyzer {
    inner: TreeSitterAnalyzer<KotlinAdapter>,
    /// Kotlin's share of the JVM dependency realm: the same jar-backed index
    /// Java and Scala consult, built from the same discovered Maven/Gradle
    /// artifacts. Built lazily because opening jars is expensive and many
    /// workspaces never ask a question that needs it.
    jvm_config: JvmAnalyzerConfig,
    external_index: Arc<OnceLock<JvmExternalDeclarationIndex>>,
    memo_budget: u64,
    imported_code_units: Cache<ProjectFile, Arc<HashSet<CodeUnit>>>,
    referencing_files: Cache<ProjectFile, Arc<HashSet<ProjectFile>>>,
    reverse_import_index: Arc<PoolSafeMemo<HashMap<ProjectFile, Arc<HashSet<ProjectFile>>>>>,
    same_package_reference_index:
        Arc<PoolSafeMemo<HashMap<ProjectFile, Arc<HashSet<ProjectFile>>>>>,
    top_level_declarations_by_package: Arc<OnceLock<HashMap<String, Arc<Vec<CodeUnit>>>>>,
}

crate::analyzer::impl_forward_query_provider!(KotlinAnalyzer);

impl KotlinAnalyzer {
    pub fn new(project: Arc<dyn Project>) -> Self {
        Self::new_with_config(project, AnalyzerConfig::default())
    }

    pub fn new_with_config(project: Arc<dyn Project>, config: AnalyzerConfig) -> Self {
        let memo_budget = config.memo_cache_budget_bytes();
        let jvm_config = config.jvm.clone();
        let inner = TreeSitterAnalyzer::new_with_config(project, KotlinAdapter, config);
        Self::from_inner(inner, memo_budget, jvm_config)
    }

    fn from_inner(
        inner: TreeSitterAnalyzer<KotlinAdapter>,
        memo_budget: u64,
        jvm_config: JvmAnalyzerConfig,
    ) -> Self {
        Self {
            inner,
            jvm_config,
            external_index: Arc::new(OnceLock::new()),
            memo_budget,
            imported_code_units: build_weighted_cache(memo_budget / 4, weight_code_unit_set),
            referencing_files: build_weighted_cache(memo_budget / 8, weight_project_file_set),
            reverse_import_index: Arc::new(PoolSafeMemo::new()),
            same_package_reference_index: Arc::new(PoolSafeMemo::new()),
            top_level_declarations_by_package: Arc::new(OnceLock::new()),
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
        let memo_budget = config.memo_cache_budget_bytes();
        let jvm_config = config.jvm.clone();
        let inner = TreeSitterAnalyzer::new_with_config_storage_context_and_progress(
            project,
            KotlinAdapter,
            config,
            store_context,
            progress,
        )?;
        Ok(Self::from_inner(inner, memo_budget, jvm_config))
    }

    pub(crate) fn clone_with_project(&self, project: Arc<dyn Project>) -> Self {
        // A different project root means different files and a different
        // classpath, so nothing derived from either survives the move.
        Self::from_inner(
            self.inner.clone_with_project(project),
            self.memo_budget,
            self.jvm_config.clone(),
        )
    }

    /// Kotlin's view of the shared JVM dependency realm.
    // Exercised by `analyzer::jvm::external`'s tests today; the type-name
    // resolution ladder that reads it in normal operation lands next, at which
    // point this attribute goes away.
    #[allow(dead_code)]
    pub(crate) fn external_declaration_index(&self) -> &JvmExternalDeclarationIndex {
        self.external_index.get_or_init(|| {
            JvmExternalDeclarationIndex::build_for_project(&self.jvm_config, self.inner.project())
        })
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
        // Every import- and package-derived index is rebuilt from the new
        // generation: an edit anywhere can add, remove, or rename a
        // declaration that some other file's import resolves to.
        let mut updated = Self::from_inner(
            self.inner.update(changed_files),
            self.memo_budget,
            self.jvm_config.clone(),
        );
        // A touched build manifest can add or drop dependencies, so the
        // jar-backed index is discarded and rebuilt on demand; every other
        // edit leaves the classpath alone and the existing index stands.
        if !changed_files.iter().any(is_jvm_dependency_input) {
            updated.external_index = Arc::clone(&self.external_index);
        }
        updated
    }

    fn update_all(&self) -> Self {
        Self::from_inner(
            self.inner.update_all(),
            self.memo_budget,
            self.jvm_config.clone(),
        )
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
