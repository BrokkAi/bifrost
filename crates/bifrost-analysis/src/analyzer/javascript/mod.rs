use crate::analyzer::clone_detection::{
    CloneCandidateProfile, detect_structural_clone_smells, refine_clone_similarity_with_ast,
};
use crate::analyzer::common::language_for_file as file_language;
use crate::analyzer::js_ts::cache::JsTsMemoCaches;
use crate::analyzer::js_ts::clones::build_js_ts_clone_candidate_data;
use crate::analyzer::js_ts::diagnostics::collect_javascript_semantic_diagnostics;
use crate::analyzer::js_ts::providers::{self, JsTsMemoSource};
use crate::analyzer::js_ts::{
    contains_tests as js_ts_contains_tests, path_contains_tests as js_ts_path_contains_tests,
    source_contains_tests as js_ts_source_contains_tests,
    synthesize_hydrated_module as synthesize_js_ts_hydrated_module_unit,
};
use crate::analyzer::tree_sitter_analyzer::lookup_suffix_candidates;
use crate::analyzer::usages::js_ts_graph::JsTsUsageIndex;
use crate::analyzer::{
    AliasResolver, AnalyzerConfig, AnalyzerStoreContext, BuildProgress, CodeUnit, IAnalyzer,
    ImportAnalysisProvider, ImportInfo, Language, LanguageAdapter, Project, ProjectFile,
    SignatureMetadata, TestAssertionSmell, TestAssertionWeights, TestDetectionProvider,
    TreeSitterAnalyzer, TypeHierarchyProvider,
};
use crate::hash::{HashMap, HashSet};
use crate::{CloneSmell, CloneSmellWeights};
use brokk_bifrost_js_ts::imports::extract_js_ts_call_receiver;
use brokk_bifrost_js_ts::javascript::*;
use brokk_bifrost_js_ts::model::{module_code_unit, module_scoped_field_uses_file_name};
use brokk_bifrost_js_ts::providers::JsTsSource;
use brokk_bifrost_js_ts::queries::JAVASCRIPT_QUERY_DIRECTORY;
use brokk_bifrost_js_ts::test_detection::detect_js_ts_test_assertion_smells;
use std::collections::BTreeSet;
use std::sync::Arc;
use tree_sitter::Tree;

mod semantic;

#[derive(Debug, Clone, Default)]
pub struct JavascriptAdapter;

impl LanguageAdapter for JavascriptAdapter {
    fn language(&self) -> Language {
        Language::JavaScript
    }

    fn query_directory(&self) -> &'static str {
        JAVASCRIPT_QUERY_DIRECTORY
    }

    fn file_extension(&self) -> &'static str {
        "js"
    }

    fn should_persist_code_unit(&self, code_unit: &CodeUnit) -> bool {
        !code_unit.is_file_scope() && !code_unit.is_module()
    }

    fn lookup_candidate_short_names(&self, normalized_fq_name: &str) -> Vec<String> {
        lookup_suffix_candidates(normalized_fq_name, &["."])
    }

    fn storage_contains_tests(
        &self,
        state: &crate::analyzer::tree_sitter_analyzer::FileState,
    ) -> bool {
        js_ts_source_contains_tests(&state.source)
    }

    fn hydrate_contains_tests(&self, stored: bool, file: &ProjectFile, source: &str) -> bool {
        stored || js_ts_path_contains_tests(file) || js_ts_source_contains_tests(source)
    }

    fn synthesize_hydrated_units(
        &self,
        file: &ProjectFile,
        source: &str,
        state: &mut crate::analyzer::tree_sitter_analyzer::FileState,
    ) {
        synthesize_js_ts_hydrated_module_unit(file, source, state);
    }

    fn path_synthetic_module_unit(&self, file: &ProjectFile) -> Option<CodeUnit> {
        Some(module_code_unit(file))
    }

    fn has_path_synthetic_module_units(&self) -> bool {
        true
    }

    fn path_synthetic_module_requires_imports(&self) -> bool {
        true
    }

    fn include_path_synthetic_module(&self, has_structured_imports: bool) -> bool {
        has_structured_imports
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
        parse_javascript_file(file, source, tree)
    }

    fn cognitive_complexity_config(
        &self,
    ) -> Option<&'static crate::analyzer::cognitive_complexity::Config> {
        Some(crate::analyzer::js_ts::cognitive_complexity_config())
    }
}

#[derive(Clone)]
pub struct JavascriptAnalyzer {
    inner: TreeSitterAnalyzer<JavascriptAdapter>,
    memo_budget: u64,
    memo_caches: Arc<JsTsMemoCaches>,
    /// Shared jsconfig/tsconfig path-alias resolver (parsed configs cached) so the
    /// import/reference graph resolves `@/`-style aliases like the scan_usages graph.
    alias_resolver: Arc<AliasResolver>,
}

impl JsTsSource for JavascriptAnalyzer {
    fn alias_resolver(&self) -> &Arc<AliasResolver> {
        &self.alias_resolver
    }

    fn language(&self) -> Language {
        Language::JavaScript
    }

    fn all_files(&self) -> Vec<ProjectFile> {
        self.inner.all_files()
    }

    fn bulk_import_infos(&self, files: &[ProjectFile]) -> HashMap<ProjectFile, Vec<ImportInfo>> {
        self.inner.bulk_import_infos(files.iter().cloned())
    }

    fn raw_supertypes_of(&self, code_unit: &CodeUnit) -> Vec<String> {
        self.inner.raw_supertypes_of(code_unit)
    }

    fn import_statements(&self, file: &ProjectFile) -> Vec<String> {
        self.inner.import_statements(file)
    }

    fn is_type_alias(&self, code_unit: &CodeUnit) -> bool {
        self.inner.is_type_alias(code_unit)
    }

    fn raw_signatures(&self, code_unit: &CodeUnit) -> Vec<String> {
        self.inner.signatures_vec_of(code_unit)
    }

    fn usage_definitions(&self) -> &dyn brokk_bifrost_core::analyzer::BoundedDefinitionLookup {
        self.inner.global_usage_definition_index_ref()
    }

    fn usage_index(
        &self,
        cancellation: Option<&crate::cancellation::CancellationToken>,
    ) -> Option<Arc<JsTsUsageIndex>> {
        cancellation.map_or_else(
            || Some(providers::jsts_usage_index(self)),
            |token| providers::jsts_usage_index_with_cancellation(self, token),
        )
    }
}

impl JsTsMemoSource for JavascriptAnalyzer {
    fn memo_caches(&self) -> &JsTsMemoCaches {
        &self.memo_caches
    }
}

crate::analyzer::impl_forward_query_provider!(JavascriptAnalyzer);

impl JavascriptAnalyzer {
    pub(crate) fn clone_with_project(&self, project: Arc<dyn Project>) -> Self {
        // The clone keeps this analyzer's `alias_resolver`, whose config memo is
        // keyed on the root it was built with. Re-projecting is a same-root
        // operation (the only caller wraps the same project in an overlay), and
        // the shared resolver every JS/TS resolution path now reads would answer
        // for the wrong tree if that stopped holding.
        debug_assert_eq!(
            self.inner.project().root(),
            project.root(),
            "re-projecting a JS/TS analyzer must not change its root"
        );
        let mut clone = self.clone();
        clone.inner = clone.inner.clone_with_project(project);
        clone
    }

    pub fn new(project: Arc<dyn Project>) -> Self {
        Self::new_with_config(project, AnalyzerConfig::default())
    }

    pub(crate) fn prewarm_jsts_usage_index(&self) -> Arc<JsTsUsageIndex> {
        providers::prewarm_jsts_usage_index(self)
    }

    pub fn new_with_config(project: Arc<dyn Project>, config: AnalyzerConfig) -> Self {
        let memo_budget = config.memo_cache_budget_bytes();
        let alias_resolver = Arc::new(AliasResolver::new(project.root().to_path_buf()));
        Self {
            inner: TreeSitterAnalyzer::new_with_config(project, JavascriptAdapter, config),
            memo_budget,
            memo_caches: Arc::new(JsTsMemoCaches::new(memo_budget)),
            alias_resolver,
        }
    }

    pub(crate) fn new_with_config_store_context(
        project: Arc<dyn Project>,
        config: AnalyzerConfig,
        store_context: AnalyzerStoreContext,
        progress: Option<BuildProgress>,
    ) -> Result<Self, crate::analyzer::store::StoreError> {
        let memo_budget = config.memo_cache_budget_bytes();
        let alias_resolver = Arc::new(AliasResolver::new(project.root().to_path_buf()));
        let inner = TreeSitterAnalyzer::new_with_config_storage_context_and_progress(
            project,
            JavascriptAdapter,
            config,
            store_context,
            progress,
        )?;
        Ok(Self {
            inner,
            memo_budget,
            memo_caches: Arc::new(JsTsMemoCaches::new(memo_budget)),
            alias_resolver,
        })
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

    pub(crate) fn ranges_limited(
        &self,
        code_unit: &CodeUnit,
        limit: usize,
    ) -> crate::analyzer::store::LimitedQueryRows<crate::analyzer::Range> {
        self.inner.ranges_limited(code_unit, limit)
    }

    pub fn extract_type_identifiers(&self, source: &str) -> BTreeSet<String> {
        extract_js_type_identifiers(source)
    }
}
impl ImportAnalysisProvider for JavascriptAnalyzer {
    fn imported_code_units_of(&self, file: &ProjectFile) -> HashSet<CodeUnit> {
        providers::imported_code_units_of(self, file)
    }

    fn referencing_files_of(&self, file: &ProjectFile) -> HashSet<ProjectFile> {
        providers::referencing_files_of(self, file)
    }

    fn import_info_of(&self, file: &ProjectFile) -> Vec<ImportInfo> {
        self.inner.import_info_of(file)
    }

    fn import_infos_for_files(
        &self,
        files: &[ProjectFile],
    ) -> Option<HashMap<ProjectFile, Vec<ImportInfo>>> {
        providers::import_infos_for_files(self, files)
    }

    fn imported_code_units_from_infos(
        &self,
        file: &ProjectFile,
        imports: &[ImportInfo],
    ) -> Option<HashSet<CodeUnit>> {
        providers::imported_code_units_from_infos(self, file, imports)
    }

    fn imported_files_from_infos(
        &self,
        file: &ProjectFile,
        imports: &[ImportInfo],
    ) -> Option<HashSet<ProjectFile>> {
        providers::imported_files_from_infos(self, file, imports)
    }

    fn relevant_imports_for(&self, code_unit: &CodeUnit) -> HashSet<String> {
        providers::relevant_imports_for(self, code_unit)
    }

    fn could_import_file(
        &self,
        source_file: &ProjectFile,
        imports: &[ImportInfo],
        target: &ProjectFile,
    ) -> bool {
        providers::could_import_file(self, source_file, imports, target)
    }
}

impl TypeHierarchyProvider for JavascriptAnalyzer {
    fn get_direct_ancestors(&self, code_unit: &CodeUnit) -> Vec<CodeUnit> {
        providers::get_direct_ancestors(self, code_unit)
    }

    fn get_direct_descendants(&self, code_unit: &CodeUnit) -> HashSet<CodeUnit> {
        providers::get_direct_descendants(self, code_unit)
    }
}

impl TestDetectionProvider for JavascriptAnalyzer {}
use crate::analyzer::CodeUnitIndex;

impl CodeUnitIndex for JavascriptAnalyzer {
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

    fn location_declarations(&self, file: &ProjectFile) -> BTreeSet<CodeUnit> {
        self.inner.location_declarations(file)
    }

    fn location_ranges(&self, code_unit: &CodeUnit) -> Vec<crate::analyzer::Range> {
        self.inner.location_ranges(code_unit)
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

    fn materialization_records(
        &self,
        file: &ProjectFile,
    ) -> Vec<crate::analyzer::structural::materialization::MaterializationRecord> {
        self.inner.materialization_records(file)
    }

    fn definitions(&self, fq_name: &str) -> Box<dyn Iterator<Item = CodeUnit> + '_> {
        self.inner.definitions(fq_name)
    }

    fn direct_children(&self, code_unit: &CodeUnit) -> Vec<CodeUnit> {
        self.inner.direct_children(code_unit)
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

    fn project(&self) -> &dyn Project {
        self.inner.project()
    }

    fn parent_of(&self, code_unit: &CodeUnit) -> Option<CodeUnit> {
        self.inner.structural_parent_of(code_unit).or_else(|| {
            module_scoped_field_uses_file_name(code_unit)
                .then(|| self.inner.top_level_file_scope_parent_of(code_unit))
                .flatten()
        })
    }

    fn get_skeleton(&self, code_unit: &CodeUnit) -> Option<String> {
        providers::module_import_skeleton(self, code_unit)
            .or_else(|| self.inner.get_skeleton(code_unit))
    }

    fn get_skeleton_header(&self, code_unit: &CodeUnit) -> Option<String> {
        providers::module_import_skeleton(self, code_unit)
            .or_else(|| self.inner.get_skeleton_header(code_unit))
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

    fn search_definitions_with_literal(
        &self,
        pattern: &str,
        required_literal: &str,
        language: Language,
    ) -> BTreeSet<CodeUnit> {
        self.inner
            .search_definitions_with_literal(pattern, required_literal, language)
    }

    fn lookup_candidates_by_short_name(&self, symbol: &str) -> BTreeSet<CodeUnit> {
        self.inner.lookup_candidates_by_short_name(symbol)
    }

    // #1088: every other language wrapper (TypeScript, Ruby, PHP, Go, Python,
    // C#, C++, Java, Rust, Scala) forwards this to the shared
    // `lookup_declarations_by_identifier`; JavaScript never did, so bare-name
    // identifier resolution silently returned nothing for JS delegates and
    // fell through to whatever another language/analyzer's `definitions()`
    // exact-match happened to find (dayjs's `formats`: a JS locale field's
    // bare identifier lookup returned empty, so the TypeScript `ILocale`
    // interface member won by default with no ambiguity ever reported).
    fn lookup_candidates_by_identifier(&self, identifier: &str) -> BTreeSet<CodeUnit> {
        self.inner.lookup_declarations_by_identifier(identifier)
    }
}

impl IAnalyzer for JavascriptAnalyzer {
    fn invalidate_cached_file_identities(&self) {
        self.inner.invalidate_cached_file_identities();
    }

    #[cfg(any(test, feature = "test-support"))]
    fn test_hooks(&self) -> &dyn crate::analyzer::AnalyzerTestHooks {
        self
    }

    fn begin_query(&self, context: &Arc<crate::analyzer::AnalyzerQueryContext>) {
        self.inner.begin_query(context);
    }

    fn end_query(&self, context: &Arc<crate::analyzer::AnalyzerQueryContext>) {
        self.inner.end_query(context);
    }

    fn begin_streaming_file_read(&self, file: &ProjectFile) {
        self.inner.begin_streaming_file_read(file);
    }

    fn end_streaming_file_read(&self, file: &ProjectFile) {
        self.inner.end_streaming_file_read(file);
    }

    fn release_streaming_readers(&self) {
        self.inner.release_streaming_readers();
    }

    fn workspace_file_index_cell(&self) -> Option<crate::analyzer::WorkspaceFileIndexCell> {
        self.inner.workspace_file_index_cell()
    }

    fn global_usage_definition_index(&self) -> crate::analyzer::DefinitionIndexHandle<'_> {
        self.inner.global_usage_definition_index()
    }

    fn import_statements(&self, file: &ProjectFile) -> Vec<String> {
        self.inner.import_statements(file)
    }

    fn compute_cognitive_complexities(&self, file: &ProjectFile) -> Vec<(CodeUnit, u32)> {
        self.inner.compute_cognitive_complexities(file)
    }

    fn update(&self, changed_files: &BTreeSet<ProjectFile>) -> Self {
        let inner = self.inner.update(changed_files);
        // Rebuild from root so a changed jsconfig/tsconfig drops its stale parse cache.
        let alias_resolver = Arc::new(AliasResolver::new(inner.project().root().to_path_buf()));
        Self {
            inner,
            memo_budget: self.memo_budget,
            memo_caches: Arc::new(JsTsMemoCaches::new(self.memo_budget)),
            alias_resolver,
        }
    }

    fn update_all(&self) -> Self {
        let inner = self.inner.update_all();
        let alias_resolver = Arc::new(AliasResolver::new(inner.project().root().to_path_buf()));
        Self {
            inner,
            memo_budget: self.memo_budget,
            memo_caches: Arc::new(JsTsMemoCaches::new(self.memo_budget)),
            alias_resolver,
        }
    }

    fn parse_errors(&self, file: &ProjectFile) -> Option<Vec<crate::analyzer::ParseError>> {
        self.inner.parse_errors(file)
    }

    fn semantic_diagnostics(
        &self,
        file: &ProjectFile,
        source: &str,
    ) -> crate::analyzer::SemanticDiagnosticReport {
        let diagnostics =
            collect_javascript_semantic_diagnostics(self, file, source, &self.alias_resolver)
                .into_iter()
                .map(Into::into)
                .collect();
        crate::analyzer::SemanticDiagnosticReport::from_workspace_absences(file, diagnostics)
    }

    fn extract_call_receiver(&self, reference: &str) -> Option<String> {
        self.inner.extract_call_receiver(reference)
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

    fn search_symbol_candidates(
        &self,
        patterns: &crate::analyzer::SearchSymbolPatternBatch,
        cancellation: Option<&crate::CancellationToken>,
    ) -> crate::analyzer::SearchSymbolCandidates {
        self.inner.search_symbol_candidates(patterns, cancellation)
    }

    fn import_analysis_provider(&self) -> Option<&dyn ImportAnalysisProvider> {
        Some(self)
    }

    fn test_detection_provider(&self) -> Option<&dyn TestDetectionProvider> {
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

    fn snapshot_caches(&self) -> Option<&crate::analyzer::AnalyzerSnapshotCaches> {
        Some(self.inner.snapshot_caches())
    }

    fn contains_tests(&self, file: &ProjectFile) -> bool {
        self.inner.contains_tests(file)
    }

    fn in_test_region(&self, code_unit: &crate::analyzer::CodeUnit) -> bool {
        self.inner.in_test_region(code_unit)
    }

    fn find_test_assertion_smells(
        &self,
        file: &ProjectFile,
        weights: TestAssertionWeights,
    ) -> Vec<TestAssertionSmell> {
        if !self.contains_tests(file) || file_language(file) != Language::JavaScript {
            return Vec::new();
        }
        let Ok(source) = self.inner.project().read_source(file) else {
            return Vec::new();
        };
        detect_js_ts_test_assertion_smells(
            file,
            &source,
            tree_sitter_javascript::LANGUAGE.into(),
            &weights,
        )
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
            .filter(|file| file_language(file) == Language::JavaScript)
            .cloned()
            .collect();
        if requested_files.is_empty() {
            return Vec::new();
        }

        let all_candidates: Vec<CloneCandidateProfile> = self
            .get_all_declarations()
            .into_iter()
            .filter(|code_unit| {
                code_unit.is_function()
                    && matches!(file_language(code_unit.source()), Language::JavaScript)
            })
            .filter_map(|code_unit| {
                build_js_ts_clone_candidate_data(
                    self,
                    &code_unit,
                    weights,
                    tree_sitter_javascript::LANGUAGE.into(),
                )
            })
            .map(|candidate| CloneCandidateProfile::create(candidate, weights))
            .collect();
        if all_candidates.is_empty() {
            return Vec::new();
        }

        detect_structural_clone_smells(
            &requested_files,
            all_candidates,
            weights,
            refine_clone_similarity_with_ast,
        )
    }
}

#[cfg(any(test, feature = "test-support"))]
impl crate::analyzer::AnalyzerTestHooks for JavascriptAnalyzer {
    fn reset_global_usage_definition_index_build_count_for_test(&self) {
        self.inner
            .test_hooks()
            .reset_global_usage_definition_index_build_count_for_test();
    }

    fn global_usage_definition_index_build_count_for_test(&self) -> usize {
        self.inner
            .test_hooks()
            .global_usage_definition_index_build_count_for_test()
    }

    fn reset_full_declaration_scan_count_for_test(&self) {
        self.inner
            .test_hooks()
            .reset_full_declaration_scan_count_for_test();
    }

    fn full_declaration_scan_count_for_test(&self) -> usize {
        self.inner
            .test_hooks()
            .full_declaration_scan_count_for_test()
    }

    fn reset_candidate_hydration_count_for_test(&self) {
        self.inner.reset_full_hydration_count_for_test();
    }

    fn candidate_hydration_count_for_test(&self) -> usize {
        self.inner.full_hydration_count_for_test() + self.inner.bulk_hydration_count_for_test()
    }

    fn reset_workspace_path_scan_count_for_test(&self) {
        self.inner
            .test_hooks()
            .reset_workspace_path_scan_count_for_test();
    }

    fn workspace_path_scan_count_for_test(&self) -> usize {
        self.inner.test_hooks().workspace_path_scan_count_for_test()
    }
}
