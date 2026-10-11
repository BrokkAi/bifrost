use crate::analyzer::clone_detection::detect_language_structural_clone_smells;
use crate::analyzer::common::language_for_file as file_language;
use crate::analyzer::js_ts::cache::JsTsMemoCaches;
use crate::analyzer::js_ts::clones::build_js_ts_clone_candidate_data;
use crate::analyzer::js_ts::diagnostics::collect_javascript_semantic_diagnostics;
use crate::analyzer::js_ts::providers::{self, JsTsMemoSource};
use crate::analyzer::js_ts::{
    contains_tests as js_ts_contains_tests,
    synthesize_hydrated_module as synthesize_js_ts_hydrated_module_unit,
    synthesize_summary_module as synthesize_js_ts_summary_module_unit,
};
use crate::analyzer::tree_sitter_analyzer::{
    DOT_LOOKUP_CANDIDATE_SEPARATORS, lookup_suffix_candidates,
};
use crate::analyzer::usages::js_ts_graph::JsTsUsageIndex;
use crate::analyzer::{
    AliasResolver, AnalyzerConfig, AnalyzerStoreContext, BuildProgress, CodeUnit, IAnalyzer,
    ImportAnalysisProvider, ImportInfo, Language, LanguageAdapter, Project, ProjectFile,
    SignatureMetadata, TestAssertionSmell, TestAssertionWeights, TestDetectionProvider,
    TreeSitterAnalyzer, TypeHierarchyProvider,
};
use crate::analyzer::{AnalyzerQueryScope, QueryScope};
use crate::hash::{HashMap, HashSet};
use crate::{CloneSmell, CloneSmellWeights};
use brokk_bifrost_core::analyzer::model::LanguageDialect;
use brokk_bifrost_core::analyzer::query_token::QueryToken;
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

/// The cache `lang` key that rows extracted from a `.jsx` file live under.
///
/// Shaped like the TypeScript pair (`typescript:ts` / `typescript:tsx`) and the
/// C++ pair (`cpp` / `cpp:c`): `.jsx` is read by the TSX grammar rather than
/// tree-sitter-javascript (#3322), so one blob has two possible projections and
/// `blobs`/`code_units`, keyed `(blob_oid, lang)`, must not let them collide.
/// The plain `javascript` key keeps its spelling so `.js` rows already in a
/// warm cache stay addressable.
pub(crate) const JAVASCRIPT_JSX_STORAGE_LANGUAGE_KEY: &str = "javascript:jsx";

#[derive(Debug, Clone, Default)]
pub struct JavascriptAdapter;

impl LanguageAdapter for JavascriptAdapter {
    fn source_fact_storage(&self) -> Option<&'static crate::analyzer::store::SourceFactStorage> {
        Some(&crate::analyzer::js_ts::source_publication::SOURCE_STORAGE)
    }

    fn requires_source_declaration_metadata_bridges(&self) -> bool {
        true
    }

    fn produces_canonical_source_facts(&self) -> bool {
        true
    }

    fn js_ts_source_facts_version(&self) -> Option<i64> {
        Some(brokk_bifrost_core::analyzer::js_ts_facts::JS_TS_SOURCE_FACTS_VERSION)
    }

    fn language(&self) -> Language {
        Language::JavaScript
    }

    fn query_directory(&self) -> &'static str {
        JAVASCRIPT_QUERY_DIRECTORY
    }

    fn file_extension(&self) -> &'static str {
        "js"
    }

    /// The `.js`/`.jsx` split applies only to files whose OWN language is
    /// JavaScript, for the reason `TypescriptAdapter` states for `.ts`/`.tsx`:
    /// the cross-adapter row guards discriminate on this answer, so a foreign
    /// file must answer its own language's key.
    fn storage_language_key_for_file(&self, file: &ProjectFile) -> &'static str {
        let own_language = file_language(file);
        if own_language != Language::JavaScript {
            return own_language.config_label();
        }
        if LanguageDialect::for_path(Language::JavaScript, file.rel_path())
            == LanguageDialect::JavaScriptJsx
        {
            return JAVASCRIPT_JSX_STORAGE_LANGUAGE_KEY;
        }
        Language::JavaScript.config_label()
    }

    fn storage_language_keys(&self) -> Vec<(String, tree_sitter::Language)> {
        vec![
            (
                Language::JavaScript.config_label().to_string(),
                tree_sitter_javascript::LANGUAGE.into(),
            ),
            (
                JAVASCRIPT_JSX_STORAGE_LANGUAGE_KEY.to_string(),
                tree_sitter_typescript::LANGUAGE_TSX.into(),
            ),
        ]
    }

    fn should_persist_code_unit(&self, code_unit: &CodeUnit) -> bool {
        crate::analyzer::common::should_persist_code_unit(code_unit)
    }

    fn lookup_candidate_separators(&self) -> &'static [&'static str] {
        DOT_LOOKUP_CANDIDATE_SEPARATORS
    }

    fn lookup_candidate_short_names(&self, normalized_fq_name: &str) -> Vec<String> {
        lookup_suffix_candidates(normalized_fq_name, self.lookup_candidate_separators())
    }

    fn hydrate_contains_tests(&self, stored: bool, file: &ProjectFile, _source: &str) -> bool {
        super::js_ts::hydrate_contains_tests(stored, file)
    }

    fn synthesize_hydrated_units(
        &self,
        file: &ProjectFile,
        source: &str,
        state: &mut crate::analyzer::tree_sitter_analyzer::FileState,
    ) {
        synthesize_js_ts_hydrated_module_unit(file, source, state);
    }

    fn synthesize_summary_projection(
        &self,
        file: &ProjectFile,
        source: &str,
        has_structured_imports: bool,
        projection: &mut crate::analyzer::SummaryFileProjection,
    ) {
        synthesize_js_ts_summary_module_unit(file, source, has_structured_imports, projection);
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
        js_ts_contains_tests(file, source, _tree)
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
    fn source_file_inventory(&self) -> crate::analyzer::QueryBatch<ProjectFile> {
        crate::analyzer::IAnalyzer::source_file_inventory(&self.inner)
    }

    fn source_facts(
        &self,
        file: &ProjectFile,
    ) -> Option<Arc<brokk_bifrost_js_ts::source_facts::JsTsFileSourceFacts>> {
        self.inner
            .canonical_js_ts_source_facts(file, &self.memo_caches.source_facts)
    }

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
        self.inner.bulk_import_infos_for_files(files)
    }

    crate::analyzer::tree_sitter_analyzer::delegate_inner_methods! {
        fn raw_supertypes_of(&self, code_unit: &CodeUnit) -> Vec<String>;
    }

    crate::analyzer::tree_sitter_analyzer::delegate_inner_methods! {
        fn import_statements(&self, file: &ProjectFile) -> Vec<String>;
    }

    fn is_type_alias(&self, code_unit: &CodeUnit) -> bool {
        self.inner.is_type_alias(code_unit)
    }

    fn raw_signatures(&self, code_unit: &CodeUnit) -> Vec<String> {
        self.inner.signatures_vec_of(code_unit)
    }

    fn with_usage_definitions(
        &self,
        _token: QueryToken<'_>,
        read: &mut dyn FnMut(&dyn brokk_bifrost_core::analyzer::BoundedDefinitionLookup),
    ) {
        crate::analyzer::with_analyzer_usage_definitions(self, Language::JavaScript, read);
    }

    fn usage_index(
        &self,
        cancellation: Option<&crate::cancellation::CancellationToken>,
    ) -> Option<Arc<JsTsUsageIndex>> {
        cancellation.map_or_else(
            || providers::jsts_usage_index(self),
            |token| providers::jsts_usage_index_with_cancellation(self, token),
        )
    }
}

impl JsTsMemoSource for JavascriptAnalyzer {
    fn memo_caches(&self) -> &JsTsMemoCaches {
        &self.memo_caches
    }

    fn analyzer(&self) -> &dyn crate::analyzer::IAnalyzer {
        &self.inner
    }
}

crate::analyzer::impl_forward_query_provider!(JavascriptAnalyzer);

impl JavascriptAnalyzer {
    pub(crate) fn update_all_with_progress(
        &self,
        progress: Option<crate::analyzer::BuildProgress>,
    ) -> Self {
        let inner = self.inner.update_all_with_progress(progress);
        let alias_resolver = Arc::new(AliasResolver::new(inner.shared_project()));
        Self {
            inner,
            memo_budget: self.memo_budget,
            memo_caches: Arc::new(JsTsMemoCaches::new(self.memo_budget)),
            alias_resolver,
        }
    }

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

    pub fn new_with_config(project: Arc<dyn Project>, config: AnalyzerConfig) -> Self {
        let memo_budget = config.memo_cache_budget_bytes();
        let alias_resolver = Arc::new(AliasResolver::new(Arc::clone(&project)));
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
        let alias_resolver = Arc::new(AliasResolver::new(Arc::clone(&project)));
        TreeSitterAnalyzer::try_wrap_with_config(
            config,
            |config| {
                TreeSitterAnalyzer::new_with_config_storage_context_and_progress(
                    project,
                    JavascriptAdapter,
                    config,
                    store_context,
                    progress,
                )
            },
            |inner, memo_budget| Self {
                inner,
                memo_budget,
                memo_caches: Arc::new(JsTsMemoCaches::new(memo_budget)),
                alias_resolver,
            },
        )
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

    pub(crate) fn signatures_limited(
        &self,
        code_unit: &CodeUnit,
        limit: usize,
    ) -> crate::analyzer::store::LimitedQueryRows<String> {
        self.inner.signatures_limited(code_unit, limit)
    }

    pub fn extract_type_identifiers(&self, source: &str) -> BTreeSet<String> {
        extract_js_type_identifiers(source)
    }
}
impl ImportAnalysisProvider for JavascriptAnalyzer {
    fn file_dependency_facts_for_files(
        &self,
        files: &[ProjectFile],
    ) -> Option<crate::hash::HashMap<ProjectFile, crate::analyzer::FileDependencyFacts>> {
        Some(self.inner.bulk_file_dependency_facts(files.iter().cloned()))
    }

    fn imported_code_units_of(&self, file: &ProjectFile) -> Arc<HashSet<CodeUnit>> {
        let scope = AnalyzerQueryScope::new(self);
        let token = scope.token();
        providers::imported_code_units_of(self, token, file)
    }

    fn referencing_files_of(&self, file: &ProjectFile) -> HashSet<ProjectFile> {
        let scope = AnalyzerQueryScope::new(self);
        let token = scope.token();
        providers::referencing_files_of(self, token, file)
    }

    fn import_info_of(&self, token: QueryToken<'_>, file: &ProjectFile) -> Vec<ImportInfo> {
        self.inner.import_info_of(token, file)
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
    ) -> Option<Arc<HashSet<CodeUnit>>> {
        let scope = AnalyzerQueryScope::new(self);
        let token = scope.token();
        providers::imported_code_units_from_infos(self, token, file, imports)
    }

    fn imported_files_from_infos(
        &self,
        file: &ProjectFile,
        imports: &[ImportInfo],
    ) -> Option<HashSet<ProjectFile>> {
        providers::imported_files_from_infos(self, file, imports)
    }

    fn relevant_imports_for(&self, code_unit: &CodeUnit) -> HashSet<String> {
        let scope = AnalyzerQueryScope::new(self);
        let token = scope.token();
        providers::relevant_imports_for(self, token, code_unit)
    }

    fn could_import_file(
        &self,
        source_file: &ProjectFile,
        imports: &[ImportInfo],
        target: &ProjectFile,
    ) -> bool {
        let scope = AnalyzerQueryScope::new(self);
        let token = scope.token();
        providers::could_import_file(self, token, source_file, imports, target)
    }
}

impl TypeHierarchyProvider for JavascriptAnalyzer {
    fn get_direct_ancestors(&self, code_unit: &CodeUnit) -> Vec<CodeUnit> {
        providers::get_direct_ancestors(self, code_unit)
    }

    fn get_direct_descendants(&self, code_unit: &CodeUnit) -> HashSet<CodeUnit> {
        providers::get_direct_descendants(self, code_unit)
    }

    fn get_direct_descendants_within(
        &self,
        code_unit: &CodeUnit,
        scope: &crate::analyzer::DescendantIndexScope<'_>,
    ) -> Option<HashSet<CodeUnit>> {
        providers::get_direct_descendants_within(self, code_unit, scope)
    }
}

impl TestDetectionProvider for JavascriptAnalyzer {}
use crate::analyzer::CodeUnitIndex;

impl CodeUnitIndex for JavascriptAnalyzer {
    crate::analyzer::tree_sitter_analyzer::delegate_inner_methods! {
        /// Forwarded so the request-scoped memo on the inner analyzer answers
        /// (#2679); the trait default would rebuild uncached per call.
        fn class_range_index(
        &self,
        file: &ProjectFile,
    ) -> std::sync::Arc<brokk_bifrost_core::analyzer::usages::inverted_edges::ClassRangeIndex>;
    }

    crate::analyzer::tree_sitter_analyzer::delegate_inner_methods! {
        fn enclosing_code_unit(
        &self,
        file: &ProjectFile,
        range: &crate::analyzer::Range,
    ) -> Option<CodeUnit>;
    }

    crate::analyzer::tree_sitter_analyzer::delegate_inner_methods! {
        fn enclosing_code_unit_for_lines(
            &self,
            file: &ProjectFile,
            start_line: usize,
            end_line: usize,
        ) -> Option<CodeUnit>;
    }

    crate::analyzer::tree_sitter_analyzer::delegate_inner_methods! {
        fn top_level_declarations(&self, file: &ProjectFile) -> Vec<CodeUnit>;
    }

    crate::analyzer::tree_sitter_analyzer::delegate_inner_methods! {
        fn summary_file_projection(
        &self,
        file: &ProjectFile,
    ) -> Option<Arc<crate::analyzer::SummaryFileProjection>>;
    }

    crate::analyzer::tree_sitter_analyzer::delegate_inner_methods! {
        fn analyzed_files(&self) -> Vec<ProjectFile>;
    }

    crate::analyzer::tree_sitter_analyzer::delegate_inner_methods! {
        fn indexed_source(&self, file: &ProjectFile) -> Option<String>;
    }

    crate::analyzer::tree_sitter_analyzer::delegate_inner_methods! {
        fn location_declarations(&self, file: &ProjectFile) -> BTreeSet<CodeUnit>;
    }

    crate::analyzer::tree_sitter_analyzer::delegate_inner_methods! {
        fn location_ranges(&self, code_unit: &CodeUnit) -> Vec<crate::analyzer::Range>;
    }

    crate::analyzer::tree_sitter_analyzer::delegate_inner_methods! {
        fn indexed_source_matches(&self, file: &ProjectFile, source: &str) -> bool;
    }

    crate::analyzer::tree_sitter_analyzer::delegate_inner_methods! {
        fn is_analyzed(&self, file: &ProjectFile) -> bool;
    }

    crate::analyzer::tree_sitter_analyzer::delegate_inner_methods! {
        fn retain_analyzed(&self, candidates: &[ProjectFile]) -> Vec<ProjectFile>;
    }

    fn all_declarations(&self) -> Box<dyn Iterator<Item = CodeUnit> + '_> {
        self.inner.all_declarations()
    }

    crate::analyzer::tree_sitter_analyzer::delegate_inner_methods! {
        fn declarations_sharing_name(&self, unit: &CodeUnit) -> Vec<CodeUnit>;
    }

    crate::analyzer::tree_sitter_analyzer::delegate_inner_methods! {
        fn declarations(&self, file: &ProjectFile) -> BTreeSet<CodeUnit>;
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

    crate::analyzer::tree_sitter_analyzer::delegate_inner_methods! {
        fn direct_children(&self, code_unit: &CodeUnit) -> Vec<CodeUnit>;
    }

    crate::analyzer::tree_sitter_analyzer::delegate_inner_methods! {
        fn ranges(&self, code_unit: &CodeUnit) -> Vec<crate::analyzer::Range>;
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

    crate::analyzer::tree_sitter_analyzer::delegate_inner_methods! {
        fn signature_metadata(&self, code_unit: &CodeUnit) -> Vec<SignatureMetadata>;
    }

    crate::analyzer::tree_sitter_analyzer::delegate_inner_methods! {
        fn languages(&self) -> BTreeSet<Language>;
    }

    crate::analyzer::tree_sitter_analyzer::delegate_inner_methods! {
        fn project(&self) -> &dyn Project;
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

    crate::analyzer::tree_sitter_analyzer::delegate_inner_methods! {
        fn get_source(&self, code_unit: &CodeUnit, include_comments: bool) -> Option<String>;
    }

    crate::analyzer::tree_sitter_analyzer::delegate_inner_methods! {
        fn get_sources(&self, code_unit: &CodeUnit, include_comments: bool) -> BTreeSet<String>;
    }

    crate::analyzer::tree_sitter_analyzer::delegate_inner_methods! {
        fn search_definitions(&self, pattern: &str, auto_quote: bool) -> BTreeSet<CodeUnit>;
    }

    crate::analyzer::tree_sitter_analyzer::delegate_inner_methods! {
        fn search_definitions_by_suffix_pattern(
        &self,
        pattern: &str,
        terminal_identifiers: &[String],
        language: Language,
    ) -> BTreeSet<CodeUnit>;
    }

    crate::analyzer::tree_sitter_analyzer::delegate_inner_methods! {
        fn lookup_candidates_by_short_name(&self, symbol: &str) -> BTreeSet<CodeUnit>;
    }

    // #1088: every other language wrapper (TypeScript, Ruby, PHP, Go, Python,
    // C#, C++, Java, Rust, Scala) forwards this to the shared
    // `lookup_declarations_by_identifier`; JavaScript never did, so bare-name
    // identifier resolution silently returned nothing for JS delegates and
    // fell through to whatever another language/analyzer's `definitions()`
    // exact-match happened to find (dayjs's `formats`: a JS locale field's
    // bare identifier lookup returned empty, so the TypeScript `ILocale`
    // interface member won by default with no ambiguity ever reported).
    fn has_complete_symbol_lookup_index(&self) -> bool {
        self.inner.has_complete_symbol_lookup_index()
    }

    fn lookup_candidates_by_identifier(&self, identifier: &str) -> BTreeSet<CodeUnit> {
        self.inner.lookup_declarations_by_identifier(identifier)
    }
}

impl IAnalyzer for JavascriptAnalyzer {
    crate::analyzer::tree_sitter_analyzer::delegate_inner_procedure_fact_methods!();

    fn dependency_file_evidence(
        &self,
    ) -> crate::analyzer::store::Result<crate::analyzer::semantic_model::DependencyFileEvidence>
    {
        self.inner.dependency_file_evidence()
    }

    fn dependency_file_locations(
        &self,
    ) -> crate::analyzer::store::Result<
        Vec<(
            String,
            crate::analyzer::semantic_model::DependencyEvidenceLocation,
        )>,
    > {
        self.inner.dependency_file_locations()
    }

    crate::analyzer::i_analyzer::forward_relational_definition_batch!();

    crate::analyzer::i_analyzer::forward_file_identity_invalidation!();

    fn working_tree_identity(&self) -> Option<std::sync::Arc<crate::gitblob::WorkingTreeIdentity>> {
        self.inner.working_tree_identity()
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

    crate::analyzer::tree_sitter_analyzer::delegate_inner_methods! {
        fn prefetch_definitions(&self, fq_names: &[String]);
    }

    crate::analyzer::tree_sitter_analyzer::delegate_inner_methods! {
        fn record_query_failure(&self, error: crate::analyzer::store::StoreError);
    }

    crate::analyzer::tree_sitter_analyzer::delegate_inner_methods! {
        fn workspace_file_index_cell(&self) -> Option<crate::analyzer::WorkspaceFileIndexCell>;
    }

    crate::analyzer::tree_sitter_analyzer::delegate_inner_methods! {
        fn definition_lookup_memo(
        &self,
    ) -> Option<std::sync::Arc<crate::analyzer::DefinitionLookupMemo>>;
    }

    crate::analyzer::tree_sitter_analyzer::delegate_inner_methods! {
        fn import_statements(&self, file: &ProjectFile) -> Vec<String>;
    }

    crate::analyzer::tree_sitter_analyzer::delegate_inner_methods! {
        fn compute_cognitive_complexities(&self, file: &ProjectFile) -> Vec<(CodeUnit, u32)>;
    }

    fn update(&self, changed_files: &BTreeSet<ProjectFile>) -> Self {
        let inner = self.inner.update(changed_files);
        // Rebuild from root so a changed jsconfig/tsconfig drops its stale parse cache.
        let alias_resolver = Arc::new(AliasResolver::new(inner.shared_project()));
        Self {
            inner,
            memo_budget: self.memo_budget,
            memo_caches: Arc::new(JsTsMemoCaches::new(self.memo_budget)),
            alias_resolver,
        }
    }

    fn update_all(&self) -> Self {
        self.update_all_with_progress(None)
    }

    fn parse_errors(&self, file: &ProjectFile) -> Option<Vec<crate::analyzer::ParseError>> {
        self.inner.parse_errors(file)
    }

    fn semantic_diagnostics(
        &self,
        file: &ProjectFile,
        source: &str,
    ) -> crate::analyzer::SemanticDiagnosticReport {
        collect_javascript_semantic_diagnostics(self, file, source)
    }

    crate::analyzer::tree_sitter_analyzer::delegate_inner_methods! {
        fn extract_call_receiver(&self, reference: &str) -> Option<String>;
    }

    crate::analyzer::tree_sitter_analyzer::delegate_inner_methods! {
        fn is_access_expression(&self, file: &ProjectFile, start_byte: usize, end_byte: usize) -> bool;
    }

    crate::analyzer::tree_sitter_analyzer::delegate_inner_methods! {
        fn find_nearest_declaration(
            &self,
            file: &ProjectFile,
            start_byte: usize,
            end_byte: usize,
            ident: &str,
        ) -> Option<crate::analyzer::DeclarationInfo>;
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

    crate::analyzer::tree_sitter_analyzer::delegate_inner_methods! {
        fn structural_fact_providers(
        &self,
    ) -> Vec<&dyn crate::analyzer::structural::StructuralFactProvider>;
    }

    fn snapshot_caches(&self) -> Option<&crate::analyzer::AnalyzerSnapshotCaches> {
        Some(self.inner.snapshot_caches())
    }

    crate::analyzer::tree_sitter_analyzer::delegate_inner_methods! {
        fn workspace_content_identities(
        &self,
    ) -> Option<crate::analyzer::content_identity::WorkspaceContentIdentities>;
    }

    crate::analyzer::tree_sitter_analyzer::delegate_inner_methods! {
        fn workspace_fact_indexes(
        &self,
    ) -> Vec<&dyn crate::analyzer::read_verification::WorkspaceFactIndex>;
    }

    crate::analyzer::tree_sitter_analyzer::delegate_inner_methods! {
        fn contains_tests(&self, file: &ProjectFile) -> bool;
    }

    fn in_test_region(&self, code_unit: &crate::analyzer::CodeUnit) -> bool {
        self.inner.in_test_region(code_unit)
    }

    fn find_test_assertion_smells(
        &self,
        file: &ProjectFile,
        weights: TestAssertionWeights,
    ) -> Vec<TestAssertionSmell> {
        crate::analyzer::test_assertion_smells_for_file(
            self,
            file,
            Language::JavaScript,
            |source| {
                let Some(grammar) = crate::analyzer::parser_language_for_path(
                    Language::JavaScript,
                    file.rel_path(),
                ) else {
                    return Vec::new();
                };
                detect_js_ts_test_assertion_smells(file, source, grammar, &weights)
            },
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
        detect_language_structural_clone_smells(
            self,
            files,
            weights,
            Language::JavaScript,
            |code_unit| {
                // The grammar is the one this unit's own file is parsed with,
                // not the language's default: `.jsx` is read by the TSX
                // grammar (#3322), and parsing it with tree-sitter-javascript
                // would compare an ERROR-recovery candidate against real trees.
                let grammar = crate::analyzer::parser_language_for_path(
                    Language::JavaScript,
                    code_unit.source().rel_path(),
                )?;
                build_js_ts_clone_candidate_data(self, code_unit, weights, grammar)
            },
        )
    }
}

#[cfg(any(test, feature = "test-support"))]
impl crate::analyzer::AnalyzerTestHooks for JavascriptAnalyzer {
    crate::analyzer::tree_sitter_analyzer::delegate_inner_test_hook_methods! {
        fn reset_relational_definition_batch_call_count_for_test(&self);
    }

    crate::analyzer::tree_sitter_analyzer::delegate_inner_test_hook_methods! {
        fn relational_definition_batch_call_count_for_test(&self) -> usize;
    }

    crate::analyzer::tree_sitter_analyzer::delegate_inner_test_hook_methods! {
        fn reset_definition_candidates_query_count_for_test(&self);
    }

    crate::analyzer::tree_sitter_analyzer::delegate_inner_test_hook_methods! {
        fn definition_candidates_query_count_for_test(&self) -> usize;
    }

    crate::analyzer::tree_sitter_analyzer::delegate_inner_test_hook_methods! {
        fn reset_definition_prefetch_batch_count_for_test(&self);
    }

    crate::analyzer::tree_sitter_analyzer::delegate_inner_test_hook_methods! {
        fn definition_prefetch_batch_count_for_test(&self) -> usize;
    }

    crate::analyzer::tree_sitter_analyzer::delegate_inner_test_hook_methods! {
        fn reset_full_declaration_scan_count_for_test(&self);
    }

    crate::analyzer::tree_sitter_analyzer::delegate_inner_test_hook_methods! {
        fn full_declaration_scan_count_for_test(&self) -> usize;
    }

    fn reset_candidate_hydration_count_for_test(&self) {
        self.inner.reset_full_hydration_count_for_test();
    }

    crate::analyzer::tree_sitter_analyzer::delegate_inner_test_hook_methods! {
        fn full_candidate_hydration_count_for_test(&self) -> usize;
    }

    crate::analyzer::tree_sitter_analyzer::delegate_inner_test_hook_methods! {
        fn bulk_candidate_hydration_count_for_test(&self) -> usize;
    }

    crate::analyzer::tree_sitter_analyzer::delegate_inner_test_hook_methods! {
        fn reset_workspace_path_scan_count_for_test(&self);
    }

    fn workspace_path_scan_count_for_test(&self) -> usize {
        self.inner.test_hooks().workspace_path_scan_count_for_test()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hydration_uses_persisted_facts_and_path_conventions_only() {
        let project_root =
            std::env::current_dir().expect("test working directory must be available");
        let production = ProjectFile::new(&project_root, "src/runtime.js");
        let test_file = ProjectFile::new(&project_root, "test/parallel/test-runtime.js");
        let source = r#"describe("runtime", () => {});"#;

        assert!(!JavascriptAdapter.hydrate_contains_tests(false, &production, source));
        assert!(JavascriptAdapter.hydrate_contains_tests(true, &production, ""));
        assert!(JavascriptAdapter.hydrate_contains_tests(false, &test_file, ""));
    }
}
