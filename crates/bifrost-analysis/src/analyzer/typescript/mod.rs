use crate::analyzer::clone_detection::detect_language_structural_clone_smells;
use crate::analyzer::common::language_for_file as file_language;
use crate::analyzer::{
    AliasResolver, AnalyzerConfig, AnalyzerStoreContext, BuildProgress, CodeUnit, IAnalyzer,
    ImportAnalysisProvider, ImportInfo, Language, Project, ProjectFile, SignatureMetadata,
    TestAssertionSmell, TestAssertionWeights, TestDetectionProvider, TreeSitterAnalyzer,
    TypeAliasProvider, TypeHierarchyProvider,
};
use crate::analyzer::{AnalyzerQueryScope, QueryScope};
use crate::hash::{HashMap, HashSet};
use crate::{CloneSmell, CloneSmellWeights};
use brokk_bifrost_core::analyzer::query_token::QueryToken;
use brokk_bifrost_js_ts::queries::TYPESCRIPT_QUERY_DIRECTORY;
use std::collections::BTreeSet;
use std::sync::Arc;
use tree_sitter::{Language as TsLanguage, Tree};

use crate::analyzer::js_ts::cache::JsTsMemoCaches;
use crate::analyzer::js_ts::clones::build_js_ts_clone_candidate_data;
use crate::analyzer::js_ts::diagnostics::collect_typescript_semantic_diagnostics;
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
use brokk_bifrost_js_ts::imports::extract_js_ts_call_receiver;
use brokk_bifrost_js_ts::model::{module_code_unit, module_scoped_field_uses_file_name};
use brokk_bifrost_js_ts::providers::JsTsSource;
use brokk_bifrost_js_ts::test_detection::detect_js_ts_test_assertion_smells;
use brokk_bifrost_js_ts::typescript::*;

mod semantic;

#[derive(Debug, Clone, Default)]
pub struct TypescriptAdapter;

impl crate::analyzer::LanguageAdapter for TypescriptAdapter {
    fn source_fact_storage(&self) -> Option<&'static crate::analyzer::store::SourceFactStorage> {
        Some(&crate::analyzer::js_ts::source_publication::SOURCE_STORAGE)
    }

    fn produces_canonical_source_facts(&self) -> bool {
        true
    }

    fn requires_source_declaration_metadata_bridges(&self) -> bool {
        true
    }

    fn js_ts_source_facts_version(&self) -> Option<i64> {
        Some(brokk_bifrost_core::analyzer::js_ts_facts::JS_TS_SOURCE_FACTS_VERSION)
    }

    fn language(&self) -> Language {
        Language::TypeScript
    }

    fn query_directory(&self) -> &'static str {
        TYPESCRIPT_QUERY_DIRECTORY
    }

    /// The `.ts`/`.tsx` split applies only to files whose OWN language is
    /// TypeScript. Every other file must answer its own language's key, as
    /// the trait contract (`LanguageAdapter::storage_language_key_for_file`)
    /// and the cpp override demand: the cross-adapter guards
    /// (`storage_key_and_generation`, #1189/#1805) discriminate on that
    /// answer. Returning "typescript:ts" for a foreign file (say a `.rb`
    /// file) arms those guards with this adapter's own key, so a
    /// request-scoped cross-language lookup that reaches this analyzer with
    /// the foreign file parses and persists it as TypeScript, and the
    /// phantom units flip same-name resolution session-wide (#2748).
    fn storage_language_key_for_file(&self, file: &ProjectFile) -> &'static str {
        let own_language = file_language(file);
        if own_language != Language::TypeScript {
            return own_language.config_label();
        }
        if file.rel_path().extension().is_some_and(|ext| ext == "tsx") {
            "typescript:tsx"
        } else {
            "typescript:ts"
        }
    }

    fn storage_language_keys(&self) -> Vec<(String, TsLanguage)> {
        vec![
            (
                "typescript:ts".to_string(),
                tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
            ),
            (
                "typescript:tsx".to_string(),
                tree_sitter_typescript::LANGUAGE_TSX.into(),
            ),
        ]
    }

    fn file_extension(&self) -> &'static str {
        "ts"
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
        parse_typescript_file(file, source, tree)
    }

    fn cognitive_complexity_config(
        &self,
    ) -> Option<&'static crate::analyzer::cognitive_complexity::Config> {
        Some(crate::analyzer::js_ts::cognitive_complexity_config())
    }
}

#[derive(Clone)]
pub struct TypescriptAnalyzer {
    inner: TreeSitterAnalyzer<TypescriptAdapter>,
    memo_budget: u64,
    memo_caches: Arc<JsTsMemoCaches>,
    /// Shared tsconfig path-alias resolver (parsed configs cached) so the import/reference
    /// graph resolves `@/`-style aliases the same way the scan_usages graph does.
    alias_resolver: Arc<AliasResolver>,
}

impl TypescriptAnalyzer {
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

    pub fn inner(&self) -> &TreeSitterAnalyzer<TypescriptAdapter> {
        &self.inner
    }

    fn typescript_skeleton_override(&self, code_unit: &CodeUnit) -> Option<String> {
        providers::module_import_skeleton(self, code_unit)
            .or_else(|| ts_type_alias_skeleton(self, code_unit))
    }
}

impl JsTsSource for TypescriptAnalyzer {
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
        Language::TypeScript
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
        crate::analyzer::with_analyzer_usage_definitions(self, Language::TypeScript, read);
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

impl JsTsMemoSource for TypescriptAnalyzer {
    fn memo_caches(&self) -> &JsTsMemoCaches {
        &self.memo_caches
    }

    fn analyzer(&self) -> &dyn crate::analyzer::IAnalyzer {
        &self.inner
    }
}

crate::analyzer::impl_forward_query_provider!(TypescriptAnalyzer);

impl TypescriptAnalyzer {
    pub fn clone_with_project(&self, project: Arc<dyn Project>) -> Self {
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
            inner: TreeSitterAnalyzer::new_with_config(project, TypescriptAdapter, config),
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
                    TypescriptAdapter,
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

    pub(crate) fn ranges_limited(
        &self,
        code_unit: &CodeUnit,
        limit: usize,
    ) -> crate::analyzer::store::LimitedQueryRows<crate::analyzer::Range> {
        self.inner.ranges_limited(code_unit, limit)
    }

    /// Mirrors the type-alias terminator that `signatures` appends, so a bounded read
    /// returns the same text as the unbounded one.
    pub(crate) fn signatures_limited(
        &self,
        code_unit: &CodeUnit,
        limit: usize,
    ) -> crate::analyzer::store::LimitedQueryRows<String> {
        let mut result = self.inner.signatures_limited(code_unit, limit);
        if self.inner.is_type_alias(code_unit) {
            for signature in &mut result.rows {
                if !signature.ends_with(';') {
                    signature.push(';');
                }
            }
        }
        result
    }

    crate::analyzer::tree_sitter_analyzer::delegate_inner_methods! {
        #[doc(hidden)]
        pub fn reset_full_hydration_count_for_test(&self);
    }

    crate::analyzer::tree_sitter_analyzer::delegate_inner_methods! {
        #[doc(hidden)]
        pub fn full_hydration_count_for_test(&self) -> usize;
    }

    pub fn extract_type_identifiers(&self, source: &str) -> BTreeSet<String> {
        brokk_bifrost_js_ts::identifiers::extract_js_ts_type_identifiers(
            source,
            tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
        )
    }
}

impl ImportAnalysisProvider for TypescriptAnalyzer {
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

impl TypeAliasProvider for TypescriptAnalyzer {
    fn is_type_alias(&self, code_unit: &CodeUnit) -> bool {
        self.inner.is_type_alias(code_unit)
    }
}

impl TestDetectionProvider for TypescriptAnalyzer {}

impl TypeHierarchyProvider for TypescriptAnalyzer {
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

use crate::analyzer::CodeUnitIndex;

impl CodeUnitIndex for TypescriptAnalyzer {
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
        self.typescript_skeleton_override(code_unit)
            .or_else(|| self.inner.get_skeleton(code_unit))
    }

    fn get_skeleton_header(&self, code_unit: &CodeUnit) -> Option<String> {
        self.typescript_skeleton_override(code_unit)
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

    crate::analyzer::tree_sitter_analyzer::delegate_inner_methods! {
        fn has_complete_symbol_lookup_index(&self) -> bool;
    }

    fn lookup_candidates_by_identifier(&self, identifier: &str) -> BTreeSet<CodeUnit> {
        self.inner.lookup_declarations_by_identifier(identifier)
    }

    fn signatures(&self, code_unit: &CodeUnit) -> Vec<String> {
        self.inner
            .signatures_vec_of(code_unit)
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
}

impl IAnalyzer for TypescriptAnalyzer {
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
        // Rebuild from root so a changed tsconfig.json drops its stale parse cache.
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
        collect_typescript_semantic_diagnostics(self, file, source)
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

    fn type_alias_provider(&self) -> Option<&dyn TypeAliasProvider> {
        Some(self)
    }

    fn type_hierarchy_provider(&self) -> Option<&dyn TypeHierarchyProvider> {
        Some(self)
    }

    fn test_detection_provider(&self) -> Option<&dyn TestDetectionProvider> {
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
            Language::TypeScript,
            |source| {
                let Some(grammar) = crate::analyzer::parser_language_for_path(
                    Language::TypeScript,
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
            Language::TypeScript,
            |code_unit| {
                // A `.tsx` unit is parsed with the TSX grammar; the plain
                // TypeScript grammar cannot read the JSX in it.
                let grammar = crate::analyzer::parser_language_for_path(
                    Language::TypeScript,
                    code_unit.source().rel_path(),
                )?;
                build_js_ts_clone_candidate_data(self, code_unit, weights, grammar)
            },
        )
    }
}

#[cfg(any(test, feature = "test-support"))]
impl crate::analyzer::AnalyzerTestHooks for TypescriptAnalyzer {
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
    use crate::analyzer::tree_sitter_analyzer::LanguageAdapter;

    #[test]
    fn hydration_uses_persisted_facts_and_path_conventions_only() {
        let project_root =
            std::env::current_dir().expect("test working directory must be available");
        let production = ProjectFile::new(&project_root, "src/runtime.ts");
        let test_file = ProjectFile::new(&project_root, "test/parallel/test-runtime.ts");
        let source = r#"test("runtime", () => {});"#;

        assert!(!TypescriptAdapter.hydrate_contains_tests(false, &production, source));
        assert!(TypescriptAdapter.hydrate_contains_tests(true, &production, ""));
        assert!(!TypescriptAdapter.hydrate_contains_tests(false, &test_file, ""));
    }
}
