mod adapter;
mod cache;
mod clones;
#[cfg(test)]
mod diagnostics;
mod hierarchy;
mod identity;
mod imports;
mod semantic;
mod structural;
#[cfg(test)]
mod tests;

use crate::analyzer::clone_detection::{
    CloneCandidateProfile, detect_structural_clone_smells, refine_clone_similarity_with_ast,
};
use crate::analyzer::common::language_for_file as file_language;
use crate::analyzer::languages::{
    BoundedReceiverQuery, DeadCodeBulkEdges, DeadCodeBulkPreflight, DeadCodeBulkProof,
    DeadCodeRouting, DeadCodeSupport, EdgePassId, EdgeSiteScanCtx, EdgeWeightScanCtx,
    LanguageEdgePass, LanguageEdgeSites, LanguageEdgeWeights, LanguageSupport,
    StructuralReceiverResolver, analyzable_file_count, fqn_bulk_nodes, overloaded_function_fqns,
};
use crate::analyzer::store::LimitedQueryRows;
use crate::analyzer::tree_sitter_analyzer::BulkFileStateSource;
use crate::analyzer::usages::GraphUsageAnalyzer;
use crate::analyzer::usages::cpp_graph::{
    CppDeadCodeBulkEligibility, CppUsageGraphStrategy, build_cpp_usage_edge_weights,
    build_cpp_usage_edges, dead_code_bulk_eligibility,
};
use crate::analyzer::usages::get_definition::{
    BoundedResolution, DefinitionLookupOutcome, resolve_cpp_bounded,
};
use crate::analyzer::usages::get_type::{TypeLookupOutcome, resolve_cpp_type_bounded};
use crate::analyzer::usages::workspace_graph::UsageEcosystem;
use crate::analyzer::weighted_cache::{build_weighted_cache, weight_code_unit_vec_by_unit};
use crate::analyzer::{
    AnalyzerConfig, AnalyzerStoreContext, BuildProgress, CloneSmell, CloneSmellWeights, CodeUnit,
    CppFieldLinkage, DirectDescendantIndex, ForwardQueryProvider, IAnalyzer,
    ImportAnalysisProvider, ImportInfo, Language, PoolSafeMemo, Project, ProjectFile, Range,
    SignatureMetadata, TestAssertionSmell, TestAssertionWeights, TestDetectionProvider,
    TreeSitterAnalyzer, TypeAliasProvider, TypeHierarchyProvider, resolve_analyzer,
};
use crate::hash::{HashMap, HashSet};
use moka::sync::Cache;
use std::collections::BTreeSet;
use std::sync::{Arc, OnceLock};

pub(crate) use adapter::CppAdapter;
use brokk_bifrost_cpp::clones::cpp_clone_parser;
use brokk_bifrost_cpp::compile_context::{CppCompileContext, CppCompileContexts};
use brokk_bifrost_cpp::graph::CppWorkspaceSource;
use brokk_bifrost_cpp::graph_support::CppSource;
use brokk_bifrost_cpp::identity::{CppReconciledDefinitionIndex, cpp_reconciled_definitions};
use brokk_bifrost_cpp::imports::IncludeTargetIndex;
use brokk_bifrost_cpp::test_detection::detect_cpp_test_assertion_smells;
use cache::{
    weight_code_unit_set_by_file, weight_code_unit_vec_by_file, weight_include_reachability,
    weight_project_file_set,
};
use clones::build_clone_candidate_data;

pub(crate) use brokk_bifrost_cpp::declarations::{
    cpp_sentinel_recovered_classes, is_direct_recovered_exported_class_field_declaration, node_text,
};
pub(crate) use brokk_bifrost_cpp::identity::{
    CppCallableUnitRole, CppOccurrenceClassifier, CppOccurrenceRole, cpp_callable_unit_role,
    cpp_indexed_callable_linkage, cpp_is_range_for_binding_name, cpp_occurrence_role_for_range,
};
pub(crate) use identity::{
    cpp_callable_definitions_share_identity_evidence, cpp_header_body_files_are_related,
};
#[derive(Clone)]
pub struct CppAnalyzer {
    inner: TreeSitterAnalyzer<CppAdapter>,
    memo_budget: u64,
    imported_code_units: Cache<ProjectFile, Arc<HashSet<CodeUnit>>>,
    referencing_files: Cache<ProjectFile, Arc<HashSet<ProjectFile>>>,
    direct_ancestors: Cache<CodeUnit, Arc<Vec<CodeUnit>>>,
    visible_type_units_by_file: Cache<ProjectFile, Arc<Vec<CodeUnit>>>,
    unconditional_include_reachability: Cache<(ProjectFile, ProjectFile, bool), bool>,
    /// #1134 resolution-time identity-reconciliation overlay. Maps the canonical
    /// `fq_name` a header declaration carries to the provisional out-of-line
    /// member definition `CodeUnit`s whose per-file identity extraction could not
    /// reconcile with it (the file-scope-under-using-directive shape and the
    /// template-specialization twin), keyed on the include-visible class table.
    /// Memoized per queried name; see `reconciled_definitions`.
    reconciled_definitions_by_fq: Cache<String, Arc<CppReconciledDefinitionIndex>>,
    include_target_index: Arc<OnceLock<IncludeTargetIndex>>,
    reverse_include_index: Arc<PoolSafeMemo<HashMap<ProjectFile, Arc<HashSet<ProjectFile>>>>>,
    /// `PoolSafeMemo`, not `OnceLock`: this whole-workspace build is reached
    /// from rayon workers during cold scans, and a blocking `get_or_init` parks
    /// every one of them behind the single initializer for its full duration.
    direct_descendant_index: Arc<PoolSafeMemo<DirectDescendantIndex>>,
    compile_contexts: Arc<OnceLock<CppCompileContexts>>,
    #[cfg(test)]
    type_alias_classification_count: Arc<std::sync::atomic::AtomicUsize>,
    #[cfg(any(test, feature = "test-support"))]
    authoritative_visibility_build_count: Arc<std::sync::atomic::AtomicUsize>,
    #[cfg(any(test, feature = "test-support"))]
    target_spec_scan_count: Arc<std::sync::atomic::AtomicUsize>,
    #[cfg(any(test, feature = "test-support"))]
    cpp_parent_resolution_count: Arc<std::sync::atomic::AtomicUsize>,
    #[cfg(any(test, feature = "test-support"))]
    visible_type_units_build_count: Arc<std::sync::atomic::AtomicUsize>,
    #[cfg(any(test, feature = "test-support"))]
    cpp_class_strength_parse_count: Arc<std::sync::atomic::AtomicUsize>,
}

crate::analyzer::impl_forward_query_provider!(CppAnalyzer);

impl CppAnalyzer {
    pub(crate) fn clone_with_project(&self, project: Arc<dyn Project>) -> Self {
        Self::from_inner(self.inner.clone_with_project(project), self.memo_budget)
    }

    pub fn new(project: Arc<dyn Project>) -> Self {
        Self::new_with_config(project, AnalyzerConfig::default())
    }

    pub fn new_with_config(project: Arc<dyn Project>, config: AnalyzerConfig) -> Self {
        let memo_budget = config.memo_cache_budget_bytes();
        let inner = TreeSitterAnalyzer::new_with_config(project, CppAdapter, config);
        Self::from_inner(inner, memo_budget)
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
            CppAdapter,
            config,
            store_context,
            progress,
        )?;
        Ok(Self::from_inner(inner, memo_budget))
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
            visible_type_units_by_file: build_weighted_cache(
                memo_budget / 8,
                weight_code_unit_vec_by_file,
            ),
            unconditional_include_reachability: build_weighted_cache(
                memo_budget / 8,
                weight_include_reachability,
            ),
            reconciled_definitions_by_fq: moka::sync::Cache::builder().max_capacity(2048).build(),
            include_target_index: Arc::new(OnceLock::new()),
            reverse_include_index: Arc::new(PoolSafeMemo::new()),
            direct_descendant_index: Arc::new(PoolSafeMemo::new()),
            compile_contexts: Arc::new(OnceLock::new()),
            #[cfg(test)]
            type_alias_classification_count: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            #[cfg(any(test, feature = "test-support"))]
            authoritative_visibility_build_count: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            #[cfg(any(test, feature = "test-support"))]
            target_spec_scan_count: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            #[cfg(any(test, feature = "test-support"))]
            cpp_parent_resolution_count: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            #[cfg(any(test, feature = "test-support"))]
            cpp_class_strength_parse_count: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            #[cfg(any(test, feature = "test-support"))]
            visible_type_units_build_count: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        }
    }

    /// The re-keyed reconciled definitions (if any) that belong under the
    /// canonical `fq_name` a header declaration carries, memoized per queried
    /// name. The decision is
    /// [`brokk_bifrost_cpp::identity::cpp_reconciled_definitions`]; this cell is
    /// the only thing that stayed, because `IAnalyzer::update` rebuilds it
    /// wholesale with the rest of the analyzer.
    fn reconciled_definitions(&self, fq_name: &str) -> Arc<CppReconciledDefinitionIndex> {
        self.reconciled_definitions_by_fq
            .get_with_by_ref(fq_name, || {
                Arc::new(cpp_reconciled_definitions(self, fq_name))
            })
    }

    fn with_updated_inner(&self, inner: TreeSitterAnalyzer<CppAdapter>) -> Self {
        Self {
            inner,
            memo_budget: self.memo_budget,
            imported_code_units: build_weighted_cache(
                self.memo_budget / 4,
                weight_code_unit_set_by_file,
            ),
            referencing_files: build_weighted_cache(self.memo_budget / 8, weight_project_file_set),
            direct_ancestors: build_weighted_cache(
                self.memo_budget / 8,
                weight_code_unit_vec_by_unit,
            ),
            visible_type_units_by_file: build_weighted_cache(
                self.memo_budget / 8,
                weight_code_unit_vec_by_file,
            ),
            unconditional_include_reachability: build_weighted_cache(
                self.memo_budget / 8,
                weight_include_reachability,
            ),
            reconciled_definitions_by_fq: moka::sync::Cache::builder().max_capacity(2048).build(),
            include_target_index: Arc::new(OnceLock::new()),
            reverse_include_index: Arc::new(PoolSafeMemo::new()),
            direct_descendant_index: Arc::new(PoolSafeMemo::new()),
            compile_contexts: Arc::new(OnceLock::new()),
            #[cfg(test)]
            type_alias_classification_count: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            #[cfg(any(test, feature = "test-support"))]
            authoritative_visibility_build_count: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            #[cfg(any(test, feature = "test-support"))]
            target_spec_scan_count: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            #[cfg(any(test, feature = "test-support"))]
            cpp_parent_resolution_count: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            #[cfg(any(test, feature = "test-support"))]
            cpp_class_strength_parse_count: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            #[cfg(any(test, feature = "test-support"))]
            visible_type_units_build_count: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
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
    pub(crate) fn import_statements_from_projection(&self, file: &ProjectFile) -> Vec<String> {
        self.inner
            .import_info_of(file)
            .into_iter()
            .map(|import| import.raw_snippet)
            .collect()
    }

    pub(crate) fn compile_context_for(&self, file: &ProjectFile) -> Option<&CppCompileContext> {
        self.compile_contexts
            .get_or_init(|| CppCompileContexts::load(self.inner.project()))
            .for_file(file)
    }

    pub(crate) fn prepared_syntax(
        &self,
        file: &ProjectFile,
    ) -> Option<Arc<crate::analyzer::tree_sitter_analyzer::PreparedSyntaxTree>> {
        self.inner.prepared_syntax(file)
    }

    pub(crate) fn prepared_syntax_limited_cancellable(
        &self,
        file: &ProjectFile,
        max_source_bytes: usize,
        cancellation: Option<&crate::cancellation::CancellationToken>,
    ) -> crate::analyzer::tree_sitter_analyzer::PreparedSyntaxLimitedOutcome {
        self.inner
            .prepared_syntax_limited_cancellable(file, max_source_bytes, cancellation)
    }

    pub(crate) fn bulk_file_states_for_query(&self, files: impl IntoIterator<Item = ProjectFile>) {
        self.inner
            .bulk_file_states_for_query(files, BulkFileStateSource::Include);
    }

    pub(crate) fn declaration_candidates_by_identifier_limited(
        &self,
        identifier: &str,
        limit: usize,
        continue_query: impl FnMut() -> bool,
    ) -> LimitedQueryRows<CodeUnit> {
        self.inner
            .lookup_declarations_by_identifier_limited(identifier, limit, continue_query)
    }

    pub(crate) fn declaration_candidates_by_fqn_limited(
        &self,
        fqn: &str,
        normalized: bool,
        limit: usize,
        continue_query: impl FnMut() -> bool,
    ) -> LimitedQueryRows<CodeUnit> {
        self.inner.lookup_declarations_by_persisted_fqn_limited(
            fqn,
            normalized,
            limit,
            continue_query,
        )
    }

    pub(crate) fn member_candidates_for_owner_limited(
        &self,
        owner_fqn: &str,
        name: &str,
        limit: usize,
        continue_query: impl FnMut() -> bool,
    ) -> LimitedQueryRows<CodeUnit> {
        self.inner
            .lookup_members_for_owner_name_limited(owner_fqn, name, limit, continue_query)
    }

    pub(crate) fn signature_metadata_limited(
        &self,
        code_unit: &CodeUnit,
        limit: usize,
    ) -> LimitedQueryRows<SignatureMetadata> {
        self.inner.signature_metadata_limited(code_unit, limit)
    }

    pub(crate) fn signatures_limited(
        &self,
        code_unit: &CodeUnit,
        limit: usize,
    ) -> LimitedQueryRows<String> {
        self.inner.signatures_limited(code_unit, limit)
    }

    pub(crate) fn ranges_limited(
        &self,
        code_unit: &CodeUnit,
        limit: usize,
    ) -> LimitedQueryRows<Range> {
        self.inner.ranges_limited(code_unit, limit)
    }

    #[cfg(test)]
    pub(crate) fn reset_full_hydration_count_for_test(&self) {
        self.inner.reset_full_hydration_count_for_test();
    }

    #[cfg(test)]
    pub(crate) fn full_hydration_count_for_test(&self) -> usize {
        self.inner.full_hydration_count_for_test()
    }

    pub fn structural_parent_of(&self, code_unit: &CodeUnit) -> Option<CodeUnit> {
        self.inner.structural_parent_of(code_unit)
    }

    pub(crate) fn template_metadata(
        &self,
        code_unit: &CodeUnit,
    ) -> Option<crate::analyzer::CppTemplateMetadata> {
        self.inner.cpp_template_metadata_of(code_unit)
    }

    #[doc(hidden)]
    pub fn prepared_syntax_parse_count_for_test(&self, file: &ProjectFile) -> usize {
        self.inner.prepared_syntax_parse_count_for_test(file)
    }

    #[doc(hidden)]
    pub fn reset_prepared_syntax_parse_counts_for_test(&self) {
        self.inner.reset_prepared_syntax_parse_counts_for_test();
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn unconditional_include_reachability_cache_len_for_test(&self) -> u64 {
        self.unconditional_include_reachability.run_pending_tasks();
        self.unconditional_include_reachability.entry_count()
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn record_authoritative_visibility_build_for_test(&self) {
        self.authoritative_visibility_build_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn reset_authoritative_visibility_build_count_for_test(&self) {
        self.authoritative_visibility_build_count
            .store(0, std::sync::atomic::Ordering::Relaxed);
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn authoritative_visibility_build_count_for_test(&self) -> usize {
        self.authoritative_visibility_build_count
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn record_target_spec_scan_for_test(&self) {
        self.target_spec_scan_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn reset_target_spec_scan_count_for_test(&self) {
        self.target_spec_scan_count
            .store(0, std::sync::atomic::Ordering::Relaxed);
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn target_spec_scan_count_for_test(&self) -> usize {
        self.target_spec_scan_count
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn record_cpp_parent_resolution_for_test(&self) {
        self.cpp_parent_resolution_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn record_cpp_class_strength_parse_for_test(&self) {
        self.cpp_class_strength_parse_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn reset_cpp_owner_resolution_counts_for_test(&self) {
        self.cpp_parent_resolution_count
            .store(0, std::sync::atomic::Ordering::Relaxed);
        self.cpp_class_strength_parse_count
            .store(0, std::sync::atomic::Ordering::Relaxed);
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn cpp_parent_resolution_count_for_test(&self) -> usize {
        self.cpp_parent_resolution_count
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn record_visible_type_units_build_for_test(&self) {
        self.visible_type_units_build_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn reset_visible_type_units_build_count_for_test(&self) {
        self.visible_type_units_build_count
            .store(0, std::sync::atomic::Ordering::Relaxed);
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn visible_type_units_build_count_for_test(&self) -> usize {
        self.visible_type_units_build_count
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn cpp_class_strength_parse_count_for_test(&self) -> usize {
        self.cpp_class_strength_parse_count
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    #[doc(hidden)]
    pub fn reset_enclosing_parent_query_counts_for_test(&self) {
        self.inner.reset_enclosing_parent_query_counts_for_test();
    }

    #[doc(hidden)]
    pub fn enclosing_code_unit_query_count_for_test(&self) -> usize {
        self.inner.enclosing_code_unit_query_count_for_test()
    }

    #[doc(hidden)]
    pub fn sql_definitions_query_count_for_test(&self) -> usize {
        self.inner.sql_definitions_query_count_for_test()
    }

    #[cfg(test)]
    pub(crate) fn reset_live_oid_validation_counts_for_test(&self) {
        self.inner.reset_live_oid_validation_counts_for_test();
    }

    #[cfg(test)]
    pub(crate) fn live_oid_validation_count_for_test(&self, file: &ProjectFile) -> usize {
        self.inner.live_oid_validation_count_for_test(file)
    }

    #[cfg(test)]
    pub(crate) fn reset_type_alias_classification_count_for_test(&self) {
        self.type_alias_classification_count
            .store(0, std::sync::atomic::Ordering::Relaxed);
    }

    #[cfg(test)]
    pub(crate) fn type_alias_classification_count_for_test(&self) -> usize {
        self.type_alias_classification_count
            .load(std::sync::atomic::Ordering::Relaxed)
    }
}

use crate::analyzer::CodeUnitIndex;

/// The memoized C++ products [`brokk_bifrost_cpp`]'s free functions resolve
/// through. Every method answers from an accessor `CppAnalyzer` already had, so
/// the five caches, two `OnceLock`s and two `PoolSafeMemo`s stay here and no
/// function on the other side of the crate line can reach past this surface.
impl CppSource for CppAnalyzer {
    fn include_target_index(&self) -> &IncludeTargetIndex {
        CppAnalyzer::include_target_index(self)
    }

    fn raw_supertypes_of(&self, code_unit: &CodeUnit) -> Vec<String> {
        self.inner.raw_supertypes_of(code_unit)
    }

    fn visible_type_units(&self, file: &ProjectFile) -> Arc<Vec<CodeUnit>> {
        CppAnalyzer::visible_type_units(self, file)
    }

    fn file_source(&self, file: &ProjectFile) -> Option<String> {
        self.inner.file_source(file)
    }

    fn prepared_syntax(
        &self,
        file: &ProjectFile,
    ) -> Option<Arc<crate::analyzer::tree_sitter_analyzer::PreparedSyntaxTree>> {
        CppAnalyzer::prepared_syntax(self, file)
    }

    fn cpp_field_linkage(&self, code_unit: &CodeUnit) -> Option<CppFieldLinkage> {
        if !code_unit.is_field() {
            return None;
        }
        let metadata = CppAnalyzer::signature_metadata_limited(self, code_unit, 2);
        metadata
            .complete
            .then_some(metadata.rows)
            .into_iter()
            .flatten()
            .find_map(|metadata| metadata.cpp_field_linkage())
    }

    fn cached_unconditional_include_reachability(
        &self,
        first: &ProjectFile,
        donor_source: &ProjectFile,
        reference_is_c: bool,
    ) -> Option<bool> {
        self.unconditional_include_reachability.get(&(
            first.clone(),
            donor_source.clone(),
            reference_is_c,
        ))
    }

    fn cache_unconditional_include_reachability(
        &self,
        first: &ProjectFile,
        donor_source: &ProjectFile,
        reference_is_c: bool,
        reaches: bool,
    ) {
        self.unconditional_include_reachability.insert(
            (first.clone(), donor_source.clone(), reference_is_c),
            reaches,
        );
    }

    fn structural_parent_of(&self, code_unit: &CodeUnit) -> Option<CodeUnit> {
        CppAnalyzer::structural_parent_of(self, code_unit)
    }

    fn template_metadata(
        &self,
        code_unit: &CodeUnit,
    ) -> Option<crate::analyzer::CppTemplateMetadata> {
        CppAnalyzer::template_metadata(self, code_unit)
    }

    fn compile_context_for(&self, file: &ProjectFile) -> Option<&CppCompileContext> {
        CppAnalyzer::compile_context_for(self, file)
    }

    #[cfg(any(test, feature = "test-support"))]
    fn record_cpp_parent_resolution_for_test(&self) {
        CppAnalyzer::record_cpp_parent_resolution_for_test(self);
    }

    #[cfg(any(test, feature = "test-support"))]
    fn record_cpp_class_strength_parse_for_test(&self) {
        CppAnalyzer::record_cpp_class_strength_parse_for_test(self);
    }
}

/// The C++ analyzer standing in for the dispatching analyzer.
///
/// Four resolution paths in the graph reach the workspace through the C++
/// analyzer they already hold rather than through the analyzer the query was
/// issued against; before the extraction they passed `&CppAnalyzer` straight
/// into a `&dyn IAnalyzer` parameter, so these three forwarders answer exactly
/// what that coercion did.
impl CppWorkspaceSource for CppAnalyzer {
    fn import_statements(&self, file: &ProjectFile) -> Vec<String> {
        self.import_statements_from_projection(file)
    }

    fn definitions_by_fqn(&self, fqn: &str) -> Vec<&CodeUnit> {
        // `into_shards` for the same reason as the `CppDispatch` impl: the
        // matches outlive the per-call handle, so they must borrow the shards.
        <Self as IAnalyzer>::global_usage_definition_index(self)
            .into_shards()
            .into_iter()
            .flat_map(|shard| shard.by_fqn(fqn).iter())
            .collect()
    }
}

impl CodeUnitIndex for CppAnalyzer {
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
        let _scope = crate::profiling::scope(format!("cpp.definitions[{fq_name}]"));
        let inner: Vec<CodeUnit> = {
            let _inner = crate::profiling::scope(format!("cpp.definitions.inner[{fq_name}]"));
            self.inner.definitions(fq_name).collect()
        };
        // #1134: fold in out-of-line member definitions whose per-file identity
        // extraction could not reconcile with this canonical `fq_name`, but the
        // include-visible class table confirms belong here, so a header
        // declaration and its `.cpp` definition unify at resolution time.
        let reconciled = self.reconciled_definitions(fq_name);
        if reconciled.rekeyed.is_empty() {
            return Box::new(inner.into_iter());
        }
        let mut definitions = inner;
        for unit in &reconciled.rekeyed {
            if !definitions.contains(unit) {
                definitions.push(unit.clone());
            }
        }
        Box::new(definitions.into_iter())
    }

    fn direct_children(&self, code_unit: &CodeUnit) -> Vec<CodeUnit> {
        self.inner.direct_children(code_unit)
    }

    fn ranges(&self, code_unit: &CodeUnit) -> Vec<crate::analyzer::Range> {
        let ranges = self.inner.ranges(code_unit);
        if !ranges.is_empty() {
            return ranges;
        }
        // #1134: a re-keyed reconciled definition (canonical identity, real
        // `.cpp` source) is not itself in the store; its ranges live under the
        // provisional identity extraction assigned it.
        if let Some(provisional) = self
            .reconciled_definitions(&code_unit.fq_name())
            .provisional_of
            .get(code_unit)
        {
            return self.inner.ranges(provisional);
        }
        ranges
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
        let metadata = self.inner.signature_metadata(code_unit);
        if !metadata.is_empty() {
            return metadata;
        }
        // #1134: a re-keyed reconciled definition carries the same signature
        // metadata as the provisional definition it stands in for, so its
        // callable role (`Definition`) and external linkage are visible to the
        // decl/def unification evidence -- otherwise the header declaration and
        // the `.cpp` definition are misread as an ambiguous cross-file duplicate.
        // Stored units always return non-empty here, so this never re-enters the
        // lazily-built index during its own construction.
        if let Some(provisional) = self
            .reconciled_definitions(&code_unit.fq_name())
            .provisional_of
            .get(code_unit)
        {
            return self.inner.signature_metadata(provisional);
        }
        metadata
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

    fn get_all_declarations(&self) -> Vec<CodeUnit> {
        self.inner.get_all_declarations()
    }

    fn get_definitions(&self, fq_name: &str) -> Vec<CodeUnit> {
        let mut definitions = self.inner.get_definitions(fq_name);
        // #1134: fold in out-of-line member definitions whose per-file identity
        // extraction could not reconcile with this canonical `fq_name`, but the
        // include-visible class table confirms belong here (so a header
        // declaration and its `.cpp` definition unify at query time).
        {
            let reconciled = self.reconciled_definitions(fq_name);
            for unit in &reconciled.rekeyed {
                if !definitions.contains(unit) {
                    definitions.push(unit.clone());
                }
            }
        }
        definitions
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

    fn lookup_candidates_by_identifier(&self, identifier: &str) -> BTreeSet<CodeUnit> {
        self.inner.lookup_declarations_by_identifier(identifier)
    }
}

impl IAnalyzer for CppAnalyzer {
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
        self.import_statements_from_projection(file)
    }

    fn compute_cognitive_complexities(&self, file: &ProjectFile) -> Vec<(CodeUnit, u32)> {
        self.inner.compute_cognitive_complexities(file)
    }

    fn update(&self, changed_files: &BTreeSet<ProjectFile>) -> Self {
        self.with_updated_inner(self.inner.update(changed_files))
    }

    fn update_all(&self) -> Self {
        self.with_updated_inner(self.inner.update_all())
    }

    fn parse_errors(&self, file: &ProjectFile) -> Option<Vec<crate::analyzer::ParseError>> {
        self.inner.parse_errors(file)
    }

    fn semantic_diagnostics(
        &self,
        file: &ProjectFile,
        source: &str,
    ) -> crate::analyzer::SemanticDiagnosticReport {
        crate::analyzer::SemanticDiagnosticReport::from_workspace_absences(
            file,
            brokk_bifrost_cpp::diagnostics::collect_cpp_semantic_diagnostics(self, file, source),
        )
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
        let requested_file_set: HashSet<ProjectFile> = requested_files.iter().cloned().collect();

        let mut parser = cpp_clone_parser();
        let all_candidates: Vec<CloneCandidateProfile> = self
            .get_all_declarations()
            .into_iter()
            .filter(|code_unit| {
                code_unit.is_function() && requested_file_set.contains(code_unit.source())
            })
            .filter_map(|code_unit| {
                build_clone_candidate_data(self, &code_unit, weights, &mut parser)
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

    fn test_detection_provider(&self) -> Option<&dyn TestDetectionProvider> {
        Some(self)
    }
}

#[cfg(any(test, feature = "test-support"))]
impl crate::analyzer::AnalyzerTestHooks for CppAnalyzer {
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
}

impl TypeAliasProvider for CppAnalyzer {
    fn is_type_alias(&self, code_unit: &CodeUnit) -> bool {
        #[cfg(test)]
        self.type_alias_classification_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.inner.is_type_alias(code_unit)
    }
}

static CPP_USAGE_STRATEGY: CppUsageGraphStrategy = CppUsageGraphStrategy::new();

pub(crate) struct CppSupport;

impl LanguageSupport for CppSupport {
    fn language(&self) -> Language {
        Language::Cpp
    }

    fn skips_local_declaration(&self, node: tree_sitter::Node<'_>, source: &str) -> bool {
        node.kind() == "init_declarator"
            && node.parent().is_some_and(|declaration| {
                is_direct_recovered_exported_class_field_declaration(declaration, source)
            })
    }

    fn package_separator(&self) -> &'static str {
        "::"
    }

    fn signature_metadata_limited(
        &self,
        analyzer: &dyn IAnalyzer,
        unit: &CodeUnit,
        limit: usize,
    ) -> Option<LimitedQueryRows<SignatureMetadata>> {
        resolve_analyzer::<CppAnalyzer>(analyzer)
            .map(|cpp| cpp.signature_metadata_limited(unit, limit))
    }

    fn declaration_ranges_limited(
        &self,
        analyzer: &dyn IAnalyzer,
        unit: &CodeUnit,
        limit: usize,
    ) -> Option<LimitedQueryRows<Range>> {
        resolve_analyzer::<CppAnalyzer>(analyzer).map(|cpp| cpp.ranges_limited(unit, limit))
    }

    fn forward_query_provider<'a>(
        &self,
        analyzer: &'a dyn IAnalyzer,
    ) -> Option<&'a dyn ForwardQueryProvider> {
        resolve_analyzer::<CppAnalyzer>(analyzer).map(|value| value as _)
    }

    fn ecosystem(&self) -> UsageEcosystem {
        UsageEcosystem::Cpp
    }

    fn usage_strategy(&self) -> &'static dyn GraphUsageAnalyzer {
        &CPP_USAGE_STRATEGY
    }

    fn edge_pass(&self) -> Option<&'static dyn LanguageEdgePass> {
        Some(&CppEdgePass)
    }

    fn dead_code(&self) -> DeadCodeSupport {
        DeadCodeSupport {
            strategy: None,
            bulk: Some(&CppDeadCodeBulk),
        }
    }

    fn structural_receiver(&self) -> Option<&'static dyn StructuralReceiverResolver> {
        Some(&CppSupport)
    }

    fn parser_language(&self, _flavor: crate::analyzer::ParserFlavor) -> tree_sitter::Language {
        tree_sitter_cpp::LANGUAGE.into()
    }

    fn structural_spec(&self) -> &'static dyn crate::analyzer::structural::StructuralSpec {
        &brokk_bifrost_cpp::structural::CPP_STRUCTURAL_SPEC
    }

    fn highlight_query(&self) -> Option<&'static str> {
        Some(tree_sitter_cpp::HIGHLIGHT_QUERY)
    }
}

struct CppEdgePass;

impl LanguageEdgePass for CppEdgePass {
    fn id(&self) -> EdgePassId {
        EdgePassId::Cpp
    }

    fn edge_sites(&self, ctx: &EdgeSiteScanCtx<'_>) -> Option<LanguageEdgeSites> {
        build_cpp_usage_edges(ctx.analyzer, ctx.fqns, ctx.keep_file).map(LanguageEdgeSites)
    }

    fn edge_weights(&self, ctx: &EdgeWeightScanCtx<'_>) -> Option<LanguageEdgeWeights> {
        build_cpp_usage_edge_weights(ctx.analyzer, ctx.fqns, ctx.keep_file)
            .map(LanguageEdgeWeights::Fqn)
    }
}

impl StructuralReceiverResolver for CppSupport {
    fn resolve_type_bounded(
        &self,
        query: BoundedReceiverQuery<'_>,
    ) -> BoundedResolution<TypeLookupOutcome> {
        resolve_cpp_type_bounded(
            query.analyzer,
            query.file,
            query.source,
            query.tree,
            query.site,
            query.budget,
            query.cancellation,
        )
    }

    fn resolve_definition_bounded(
        &self,
        query: BoundedReceiverQuery<'_>,
    ) -> BoundedResolution<DefinitionLookupOutcome> {
        resolve_cpp_bounded(
            query.analyzer,
            query.file,
            query.source,
            query.tree,
            query.site,
            query.budget,
            query.cancellation,
        )
    }
}

#[derive(Default)]
struct CppDeadCodeMemo {
    file_count: Option<usize>,
    overloaded_fqns: Option<HashSet<String>>,
}

struct CppDeadCodeBulk;

impl DeadCodeBulkProof for CppDeadCodeBulk {
    fn id(&self) -> EdgePassId {
        EdgePassId::Cpp
    }

    fn new_memo(&self) -> Box<dyn std::any::Any + Send> {
        Box::new(CppDeadCodeMemo::default())
    }

    fn needs_precise_scan(&self, routing: DeadCodeRouting<'_>) -> bool {
        let DeadCodeRouting {
            analyzer,
            candidate,
            file_cap,
            memo,
        } = routing;
        let CppDeadCodeMemo {
            file_count,
            overloaded_fqns,
        } = memo.downcast_mut().expect("C++ bulk memo");
        if *file_count.get_or_insert_with(|| analyzable_file_count(analyzer, Language::Cpp))
            > file_cap
        {
            return true;
        }

        let empty_overloads = HashSet::default();
        let overloads = if candidate.is_function() {
            overloaded_fqns.get_or_insert_with(|| overloaded_function_fqns(analyzer, Language::Cpp))
        } else {
            &empty_overloads
        };
        matches!(
            dead_code_bulk_eligibility(analyzer, candidate, overloads),
            CppDeadCodeBulkEligibility::NeedsPrecise
        )
    }

    fn preflight(&self, analyzer: &dyn IAnalyzer) -> DeadCodeBulkPreflight {
        DeadCodeBulkPreflight::Ready {
            label: "C++",
            files: analyzable_file_count(analyzer, Language::Cpp),
        }
    }

    fn build(
        &self,
        analyzer: &dyn IAnalyzer,
        candidates: &[CodeUnit],
    ) -> Option<DeadCodeBulkEdges> {
        let nodes = fqn_bulk_nodes(
            analyzer,
            Language::Cpp,
            |unit| unit.is_function() || unit.is_class() || unit.is_field(),
            candidates,
        );
        build_cpp_usage_edges(analyzer, &nodes, |_| true)
            .map(|edges| DeadCodeBulkEdges::Fqn(Arc::new(edges)))
    }
}
