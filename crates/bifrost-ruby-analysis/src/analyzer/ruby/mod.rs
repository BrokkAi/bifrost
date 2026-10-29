#[doc(hidden)]
pub mod adapter;
mod clones;
#[doc(hidden)]
pub mod constant_identity;
mod dependency_discovery;
pub(crate) mod diagnostics;
mod external;
mod gem_artifact;
mod hierarchy;
mod imports;
mod mixins;
mod rbs_artifact;
mod semantic;
mod source_artifact;
#[doc(hidden)]
pub mod source_facts;
pub(crate) mod source_publication;
#[doc(hidden)]
pub mod source_storage;
pub(crate) mod structural;
mod tests;
mod type_flow;

pub(crate) fn artifact_logical_path(archive_sha256: &str, entry_path: &str) -> String {
    format!("gem+sha256:{archive_sha256}!/{entry_path}")
}

fn nullable_type(type_ref: TypeRef) -> TypeRef {
    match type_ref {
        TypeRef::Named {
            name, arguments, ..
        } => TypeRef::Named {
            name,
            arguments,
            nullable: true,
        },
        TypeRef::Declared { id, arguments, .. } => TypeRef::Declared {
            id,
            arguments,
            nullable: true,
        },
        other => TypeRef::Named {
            name: "optional".to_owned(),
            arguments: vec![other],
            nullable: true,
        },
    }
}

use brokk_bifrost_analysis::analyzer::cache_weight::weight_code_unit_vec;

use brokk_bifrost_analysis::analyzer::clone_detection::detect_language_structural_clone_smells;

use brokk_bifrost_core::analyzer::common::language_for_file as file_language;

use brokk_bifrost_analysis::analyzer::languages::BoundedReceiverQuery;

use brokk_bifrost_analysis::analyzer::languages::CandidateAugmentation;

use brokk_bifrost_analysis::analyzer::languages::CandidateCtx;

use brokk_bifrost_analysis::analyzer::languages::DeadCodeBulkEdges;

use brokk_bifrost_analysis::analyzer::languages::DeadCodeBulkPreflight;

use brokk_bifrost_analysis::analyzer::languages::DeadCodeBulkProof;

use brokk_bifrost_analysis::analyzer::languages::DeadCodeRouting;

use brokk_bifrost_analysis::analyzer::languages::DeadCodeSupport;

use brokk_bifrost_analysis::analyzer::languages::EdgePassId;

use brokk_bifrost_analysis::analyzer::languages::EdgeSiteScanCtx;

use brokk_bifrost_analysis::analyzer::languages::EdgeWeightScanCtx;

use brokk_bifrost_analysis::analyzer::languages::LanguageEdgePass;

use brokk_bifrost_analysis::analyzer::languages::LanguageEdgeSites;

use brokk_bifrost_analysis::analyzer::languages::LanguageEdgeWeights;

use brokk_bifrost_analysis::analyzer::languages::LanguageSupport;

use brokk_bifrost_analysis::analyzer::languages::StructuralReceiverResolver;

use brokk_bifrost_analysis::analyzer::languages::analyzable_file_count;

use brokk_bifrost_analysis::analyzer::languages::build_fqn_bulk_edges;

use brokk_bifrost_analysis::analyzer::semantic_model::model::TypeRef;

use brokk_bifrost_core::analyzer::query_batch::LimitedQueryRows;

use brokk_bifrost_core::analyzer::type_relations::TypeRelation;

use brokk_bifrost_core::analyzer::usages::resolution_session::BoundedResolution;

use brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionLookupOutcome;

use crate::analyzer::usages::get_definition::ruby::resolve_ruby_bounded;

use brokk_bifrost_analysis::analyzer::usages::get_type::TypeLookupOutcome;

use crate::analyzer::usages::get_type::resolve_ruby_type_bounded;

use crate::analyzer::usages::ruby_graph::RubyUsageGraphStrategy;

use crate::analyzer::usages::ruby_graph::build_rooted_ruby_usage_edges;

use crate::analyzer::usages::ruby_graph::build_ruby_usage_edge_weights;

use crate::analyzer::usages::ruby_graph::build_ruby_usage_edges;

use brokk_bifrost_analysis::analyzer::usages::workspace_graph::UsageEcosystem;

use brokk_bifrost_core::analyzer::weighted_cache::build_weighted_cache;

use brokk_bifrost_core::analyzer::weighted_cache::weight_code_unit_set;

use brokk_bifrost_core::analyzer::weighted_cache::weight_project_file_set;

use brokk_bifrost_core::analyzer::config::AnalyzerConfig;

use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::AnalyzerStoreContext;

use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::BuildProgress;

use brokk_bifrost_core::analyzer::model::CloneSmell;

use brokk_bifrost_core::analyzer::model::CloneSmellWeights;

use brokk_bifrost_core::analyzer::model::CodeUnit;

use brokk_bifrost_core::analyzer::capabilities::DescendantIndexVariant;

use brokk_bifrost_core::analyzer::capabilities::DirectDescendantIndex;

use brokk_bifrost_analysis::analyzer::analyzer_definition_lookup::ForwardQueryProvider;

use brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer;

use brokk_bifrost_core::analyzer::capabilities::ImportAnalysisProvider;

use brokk_bifrost_core::analyzer::pool_memo::KeyedPoolSafeMemo;

use brokk_bifrost_core::analyzer::model::Language;

use brokk_bifrost_core::analyzer::pool_memo::PoolSafeMemo;

use brokk_bifrost_core::analyzer::project::Project;

use brokk_bifrost_core::analyzer::model::ProjectFile;

use brokk_bifrost_core::analyzer::model::Range;

use brokk_bifrost_core::analyzer::model::RubyMethodDispatchMode;

use brokk_bifrost_core::analyzer::model::SignatureMetadata;

use brokk_bifrost_core::analyzer::model::TestAssertionAnalysis;

use brokk_bifrost_core::analyzer::model::TestAssertionSmell;

use brokk_bifrost_core::analyzer::model::TestAssertionWeights;

use brokk_bifrost_core::analyzer::capabilities::TestDetectionProvider;

use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::TreeSitterAnalyzer;

use brokk_bifrost_core::analyzer::capabilities::TypeHierarchyProvider;

use brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer;

use brokk_bifrost_core::hash::HashMap;

use brokk_bifrost_core::hash::HashSet;
use moka::sync::Cache;
use std::collections::BTreeSet;

use std::sync::{Arc, OnceLock};

pub(crate) use crate::analyzer::ruby::adapter::RubyAdapter;

use crate::analyzer::ruby::clones::build_ruby_clone_candidate_data;

pub(crate) use brokk_bifrost_ruby::graph_support::RubySemanticFacts;

pub use brokk_bifrost_ruby::structural::{RubyCallResultUseIndex, ruby_call_result_use};

pub use crate::analyzer::ruby::dependency_discovery::resolve_ruby_semantic_pack_dependencies;

pub use crate::analyzer::ruby::external::RubyDependencyPackAdapter;

pub use crate::analyzer::ruby::external::RubyGemArchivePackProducer;

pub use crate::analyzer::ruby::semantic::ruby_declared_scalar_types;

#[derive(Clone)]
pub struct RubyAnalyzer {
    inner: TreeSitterAnalyzer<RubyAdapter>,
    memo_budget: u64,
    imported_code_units: Cache<ProjectFile, Arc<HashSet<CodeUnit>>>,
    referencing_files: Cache<ProjectFile, Arc<HashSet<ProjectFile>>>,
    direct_ancestors: Cache<CodeUnit, Arc<Vec<CodeUnit>>>,
    /// `PoolSafeMemo`, not `OnceLock`: this whole-workspace build is reached
    /// from rayon workers during cold scans, and a blocking `get_or_init` parks
    /// every one of them behind the single initializer for its full duration.
    /// Keyed by [`DescendantIndexVariant`]: a request that excluded test files
    /// gets an index that was never built over them (issue #1748). Two cells at
    /// most, because the exclusion verdict is a pure function of the analyzer
    /// and the file.
    direct_descendant_index: Arc<KeyedPoolSafeMemo<DescendantIndexVariant, DirectDescendantIndex>>,
    reverse_import_index: Arc<PoolSafeMemo<HashMap<ProjectFile, Arc<HashSet<ProjectFile>>>>>,
    autoload_constant_files: Arc<OnceLock<HashMap<String, HashSet<ProjectFile>>>>,
    source_readiness: Arc<OnceLock<()>>,
    zeitwerk_project: Arc<OnceLock<bool>>,
    zeitwerk_autoload_files: Arc<OnceLock<HashSet<ProjectFile>>>,
    zeitwerk_consumer_files: Arc<OnceLock<HashSet<ProjectFile>>>,
    zeitwerk_autoload_code_units: Arc<OnceLock<HashSet<CodeUnit>>>,
    #[allow(dead_code)]
    mixin_relations: Arc<OnceLock<Vec<TypeRelation>>>,
    semantic_facts: Arc<OnceLock<RubySemanticFacts>>,
    /// Class/module declarations indexed by their trailing identifier, for
    /// resolving relative (unqualified) supertype references without scanning
    /// every declaration.
    types_by_identifier: Arc<OnceLock<HashMap<String, Vec<CodeUnit>>>>,
}

brokk_bifrost_analysis::analyzer::analyzer_definition_lookup::impl_forward_query_provider!(
    RubyAnalyzer
);

impl RubyAnalyzer {
    pub(crate) fn update_all_with_progress(
        &self,
        progress: Option<brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::BuildProgress>,
    ) -> Self {
        Self::from_inner(
            self.inner.update_all_with_progress(progress),
            self.memo_budget,
        )
    }

    pub(crate) fn clone_with_project(&self, project: Arc<dyn Project>) -> Self {
        Self::from_inner(self.inner.clone_with_project(project), self.memo_budget)
    }

    pub fn new(project: Arc<dyn Project>) -> Self {
        Self::new_with_config(project, AnalyzerConfig::default())
    }

    pub fn new_with_config(project: Arc<dyn Project>, config: AnalyzerConfig) -> Self {
        TreeSitterAnalyzer::wrap_with_config(
            config,
            |config| TreeSitterAnalyzer::new_with_config(project, RubyAdapter, config),
            Self::from_inner,
        )
    }

    pub(crate) fn new_with_config_store_context(
        project: Arc<dyn Project>,
        config: AnalyzerConfig,
        store_context: AnalyzerStoreContext,
        progress: Option<BuildProgress>,
    ) -> Result<Self, brokk_bifrost_analysis::analyzer::store::StoreError> {
        TreeSitterAnalyzer::try_wrap_with_config(
            config,
            |config| {
                TreeSitterAnalyzer::new_with_config_storage_context_and_progress(
                    project,
                    RubyAdapter,
                    config,
                    store_context,
                    progress,
                )
            },
            Self::from_inner,
        )
    }

    fn from_inner(inner: TreeSitterAnalyzer<RubyAdapter>, memo_budget: u64) -> Self {
        Self {
            inner,
            memo_budget,
            imported_code_units: build_weighted_cache(memo_budget / 4, weight_code_unit_set),
            referencing_files: build_weighted_cache(memo_budget / 8, weight_project_file_set),
            direct_ancestors: build_weighted_cache(memo_budget / 8, weight_code_unit_vec),
            direct_descendant_index: Arc::new(KeyedPoolSafeMemo::new()),
            reverse_import_index: Arc::new(PoolSafeMemo::new()),
            autoload_constant_files: Arc::new(OnceLock::new()),
            source_readiness: Arc::new(OnceLock::new()),
            zeitwerk_project: Arc::new(OnceLock::new()),
            zeitwerk_autoload_files: Arc::new(OnceLock::new()),
            zeitwerk_consumer_files: Arc::new(OnceLock::new()),
            zeitwerk_autoload_code_units: Arc::new(OnceLock::new()),
            mixin_relations: Arc::new(OnceLock::new()),
            semantic_facts: Arc::new(OnceLock::new()),
            types_by_identifier: Arc::new(OnceLock::new()),
        }
    }

    pub fn from_project<P>(project: P) -> Self
    where
        P: Project + 'static,
    {
        Self::new(Arc::new(project))
    }

    /// Seed-directed Ruby reference candidates from persisted AST identifiers.
    ///
    /// Ruby records both method identifiers and constants. This lookup is only
    /// admission evidence; the graph resolver still proves each returned site
    /// from the syntax tree and receiver semantics.
    pub(crate) fn reference_candidates_for_identifier(
        &self,
        identifier: &str,
        cancellation: &brokk_bifrost_core::cancellation::CancellationToken,
    ) -> HashSet<ProjectFile> {
        if identifier.is_empty() {
            return HashSet::default();
        }
        let identifiers = HashSet::from_iter([identifier.to_string()]);
        self.inner
            .reverse_identifier_candidates(&identifiers, cancellation)
    }

    #[cfg(test)]
    pub(crate) fn global_semantic_index_initialized_for_test(&self) -> bool {
        self.semantic_facts.get().is_some()
    }

    /// Store reader checkouts, one per relational batch this analyzer has run.
    /// The definition-lookup cost pins in `analyzer_definition_lookup` read it
    /// as a delta around one call.
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn relational_batch_reader_checkouts_for_test(&self) -> usize {
        self.inner
            .analyzer_store()
            .relational_batch_counts_for_test()
            .0
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
        limit: usize,
        continue_query: impl FnMut() -> bool,
    ) -> LimitedQueryRows<CodeUnit> {
        let Some(identifier) = fqn
            // fqname-M4: leaf identifier of a `&str` fqn parameter (no CodeUnit/fq at this query boundary)
            .rsplit(['.', '$'])
            .next()
            .filter(|name| !name.is_empty())
        else {
            return LimitedQueryRows::complete(Vec::new(), 0);
        };
        let mut candidates =
            self.inner
                .lookup_declarations_by_identifier_limited(identifier, limit, continue_query);
        if candidates.complete {
            candidates
                .rows
                .retain(|candidate| candidate.fq_name() == fqn);
        }
        candidates
    }

    pub(crate) fn member_candidates_for_owner_limited(
        &self,
        owner_fqn: &str,
        name: &str,
        limit: usize,
        continue_query: impl FnMut() -> bool,
    ) -> LimitedQueryRows<CodeUnit> {
        let exact_fqn = if owner_fqn.is_empty() {
            name.to_string()
        } else {
            format!("{owner_fqn}.{name}")
        };
        self.declaration_candidates_by_fqn_limited(&exact_fqn, limit, continue_query)
    }

    brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::delegate_inner_methods! {
        pub(crate) fn direct_children_limited(
        &self,
        owner: &CodeUnit,
        limit: usize,
    ) -> LimitedQueryRows<CodeUnit>;
    }

    pub(crate) fn signature_metadata_limited(
        &self,
        unit: &CodeUnit,
        limit: usize,
    ) -> LimitedQueryRows<SignatureMetadata> {
        self.inner.signature_metadata_limited(unit, limit)
    }

    pub(crate) fn signatures_limited(
        &self,
        unit: &CodeUnit,
        limit: usize,
    ) -> LimitedQueryRows<String> {
        self.inner.signatures_limited(unit, limit)
    }

    brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::delegate_inner_methods! {
        #[doc(hidden)]
        pub fn reset_full_hydration_count_for_test(&self);
    }

    brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::delegate_inner_methods! {
        #[doc(hidden)]
        pub fn full_hydration_count_for_test(&self) -> usize;
    }

    pub(crate) fn ranges_limited(&self, unit: &CodeUnit, limit: usize) -> LimitedQueryRows<Range> {
        self.inner.ranges_limited(unit, limit)
    }

    pub(crate) fn semantic_facts(&self) -> &RubySemanticFacts {
        self.semantic_facts.get_or_init(|| {
            brokk_bifrost_analysis::analyzer::common::persistent_cache_fill(
                self,
                "ruby.semantic_facts",
                || brokk_bifrost_ruby::graph_support::build_ruby_semantic_facts(self),
            )
        })
    }

    pub(crate) fn method_dispatch_mode(&self, unit: &CodeUnit) -> RubyMethodDispatchMode {
        self.inner
            .ruby_method_dispatch_mode(unit)
            .unwrap_or(RubyMethodDispatchMode::Instance)
    }

    pub(crate) fn method_dispatch_modes_limited(
        &self,
        unit: &CodeUnit,
        limit: usize,
    ) -> LimitedQueryRows<RubyMethodDispatchMode> {
        self.inner.ruby_method_dispatch_modes_limited(unit, limit)
    }
}

use brokk_bifrost_core::analyzer::code_unit_index::CodeUnitIndex;

impl CodeUnitIndex for RubyAnalyzer {
    brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::delegate_inner_methods! {
        /// Forwarded so the request-scoped memo on the inner analyzer answers
        /// (#2679); the trait default would rebuild uncached per call.
        fn class_range_index(
        &self,
        file: &ProjectFile,
    ) -> std::sync::Arc<brokk_bifrost_core::analyzer::usages::inverted_edges::ClassRangeIndex>;
    }

    brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::delegate_inner_methods! {
        fn enclosing_code_unit(
        &self,
        file: &ProjectFile,
        range: &brokk_bifrost_analysis::analyzer::Range,
    ) -> Option<CodeUnit>;
    }

    brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::delegate_inner_methods! {
        fn enclosing_code_unit_for_lines(
            &self,
            file: &ProjectFile,
            start_line: usize,
            end_line: usize,
        ) -> Option<CodeUnit>;
    }

    brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::delegate_inner_methods! {
        fn top_level_declarations(&self, file: &ProjectFile) -> Vec<CodeUnit>;
    }

    brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::delegate_inner_methods! {
        fn summary_file_projection(
        &self,
        file: &ProjectFile,
    ) -> Option<Arc<brokk_bifrost_analysis::analyzer::SummaryFileProjection>>;
    }

    brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::delegate_inner_methods! {
        fn analyzed_files(&self) -> Vec<ProjectFile>;
    }

    brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::delegate_inner_methods! {
        fn retain_analyzed(&self, candidates: &[ProjectFile]) -> Vec<ProjectFile>;
    }

    brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::delegate_inner_methods! {
        fn indexed_source(&self, file: &ProjectFile) -> Option<String>;
    }

    brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::delegate_inner_methods! {
        fn indexed_blob_oid(&self, file: &ProjectFile) -> Option<brokk_bifrost_analysis::analyzer::Oid>;
    }

    brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::delegate_inner_methods! {
        fn location_declarations(&self, file: &ProjectFile) -> BTreeSet<CodeUnit>;
    }

    brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::delegate_inner_methods! {
        fn location_ranges(&self, code_unit: &CodeUnit) -> Vec<brokk_bifrost_analysis::analyzer::Range>;
    }

    brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::delegate_inner_methods! {
        fn indexed_source_matches(&self, file: &ProjectFile, source: &str) -> bool;
    }

    fn all_declarations(&self) -> Box<dyn Iterator<Item = CodeUnit> + '_> {
        self.inner.all_declarations()
    }

    brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::delegate_inner_methods! {
        fn declarations_sharing_name(&self, unit: &CodeUnit) -> Vec<CodeUnit>;
    }

    brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::delegate_inner_methods! {
        fn declarations(&self, file: &ProjectFile) -> BTreeSet<CodeUnit>;
    }

    fn materialization_records(
        &self,
        file: &ProjectFile,
    ) -> Vec<brokk_bifrost_core::analyzer::structural::materialization::MaterializationRecord> {
        self.inner.materialization_records(file)
    }

    fn definitions(&self, fq_name: &str) -> Box<dyn Iterator<Item = CodeUnit> + '_> {
        self.inner.definitions(fq_name)
    }

    brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::delegate_inner_methods! {
        fn direct_children(&self, code_unit: &CodeUnit) -> Vec<CodeUnit>;
    }

    brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::delegate_inner_methods! {
        fn ranges(&self, code_unit: &CodeUnit) -> Vec<brokk_bifrost_analysis::analyzer::Range>;
    }

    fn ranges_with_limit(
        &self,
        code_unit: &CodeUnit,
        max_ranges: usize,
        cancellation: &brokk_bifrost_core::cancellation::CancellationToken,
    ) -> (Vec<brokk_bifrost_core::analyzer::model::Range>, usize, bool) {
        self.inner
            .ranges_with_limit(code_unit, max_ranges, cancellation)
    }

    fn signatures(&self, code_unit: &CodeUnit) -> Vec<String> {
        self.inner.signatures(code_unit)
    }

    brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::delegate_inner_methods! {
        fn signature_metadata(&self, code_unit: &CodeUnit) -> Vec<SignatureMetadata>;
    }

    brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::delegate_inner_methods! {
        fn languages(&self) -> BTreeSet<Language>;
    }

    brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::delegate_inner_methods! {
        fn project(&self) -> &dyn Project;
    }

    fn get_skeleton(&self, code_unit: &CodeUnit) -> Option<String> {
        self.inner.get_skeleton(code_unit)
    }

    brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::delegate_inner_methods! {
        fn get_skeleton_header(&self, code_unit: &CodeUnit) -> Option<String>;
    }

    brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::delegate_inner_methods! {
        fn get_source(&self, code_unit: &CodeUnit, include_comments: bool) -> Option<String>;
    }

    brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::delegate_inner_methods! {
        fn get_sources(&self, code_unit: &CodeUnit, include_comments: bool) -> BTreeSet<String>;
    }

    brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::delegate_inner_methods! {
        fn search_definitions(&self, pattern: &str, auto_quote: bool) -> BTreeSet<CodeUnit>;
    }

    brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::delegate_inner_methods! {
        fn search_definitions_by_suffix_pattern(
        &self,
        pattern: &str,
        terminal_identifiers: &[String],
        language: Language,
    ) -> BTreeSet<CodeUnit>;
    }

    brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::delegate_inner_methods! {
        fn lookup_candidates_by_short_name(&self, symbol: &str) -> BTreeSet<CodeUnit>;
    }

    brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::delegate_inner_methods! {
        fn has_complete_symbol_lookup_index(&self) -> bool;
    }

    fn lookup_candidates_by_identifier(&self, identifier: &str) -> BTreeSet<CodeUnit> {
        self.inner.lookup_declarations_by_identifier(identifier)
    }
}

impl IAnalyzer for RubyAnalyzer {
    brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::delegate_inner_procedure_fact_methods!();

    brokk_bifrost_analysis::analyzer::i_analyzer::forward_relational_definition_batch!();

    #[cfg(any(test, feature = "test-support"))]
    fn test_hooks(&self) -> &dyn brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerTestHooks {
        self
    }

    brokk_bifrost_analysis::analyzer::i_analyzer::forward_file_identity_invalidation!();

    fn working_tree_identity(
        &self,
    ) -> Option<std::sync::Arc<brokk_bifrost_core::gitblob::WorkingTreeIdentity>> {
        self.inner.working_tree_identity()
    }

    fn begin_query(
        &self,
        context: &Arc<brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryContext>,
    ) {
        self.inner.begin_query(context);
    }

    fn end_query(
        &self,
        context: &Arc<brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryContext>,
    ) {
        self.inner.end_query(context);
    }

    brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::delegate_inner_methods! {
        fn prefetch_definitions(&self, fq_names: &[String]);
    }

    brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::delegate_inner_methods! {
        fn record_query_failure(&self, error: brokk_bifrost_analysis::analyzer::store::StoreError);
    }

    brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::delegate_inner_methods! {
        fn workspace_file_index_cell(&self) -> Option<brokk_bifrost_analysis::analyzer::WorkspaceFileIndexCell>;
    }

    brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::delegate_inner_methods! {
        fn definition_lookup_memo(
        &self,
    ) -> Option<std::sync::Arc<brokk_bifrost_analysis::analyzer::DefinitionLookupMemo>>;
    }

    brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::delegate_inner_methods! {
        fn structural_fact_providers(
        &self,
    ) -> Vec<&dyn brokk_bifrost_analysis::analyzer::structural::StructuralFactProvider>;
    }

    fn snapshot_caches(
        &self,
    ) -> Option<&brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerSnapshotCaches> {
        Some(self.inner.snapshot_caches())
    }

    brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::delegate_inner_methods! {
        fn workspace_content_identities(
        &self,
    ) -> Option<brokk_bifrost_analysis::analyzer::content_identity::WorkspaceContentIdentities>;
    }

    brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::delegate_inner_methods! {
        fn workspace_fact_indexes(
        &self,
    ) -> Vec<&dyn brokk_bifrost_analysis::analyzer::read_verification::WorkspaceFactIndex>;
    }

    brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::delegate_inner_methods! {
        fn import_statements(&self, file: &ProjectFile) -> Vec<String>;
    }

    brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::delegate_inner_methods! {
        fn compute_cognitive_complexities(&self, file: &ProjectFile) -> Vec<(CodeUnit, u32)>;
    }

    fn update(&self, changed_files: &BTreeSet<ProjectFile>) -> Self {
        Self::from_inner(self.inner.update(changed_files), self.memo_budget)
    }

    fn update_all(&self) -> Self {
        self.update_all_with_progress(None)
    }

    fn parse_errors(
        &self,
        file: &ProjectFile,
    ) -> Option<Vec<brokk_bifrost_core::analyzer::model::ParseError>> {
        self.inner.parse_errors(file)
    }

    fn semantic_diagnostics(
        &self,
        file: &ProjectFile,
        source: &str,
    ) -> brokk_bifrost_core::analyzer::model::SemanticDiagnosticReport {
        diagnostics::collect_ruby_semantic_diagnostics(self, file, source)
    }

    brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::delegate_inner_methods! {
        fn extract_call_receiver(&self, reference: &str) -> Option<String>;
    }

    brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::delegate_inner_methods! {
        fn is_access_expression(&self, file: &ProjectFile, start_byte: usize, end_byte: usize) -> bool;
    }

    brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::delegate_inner_methods! {
        fn find_nearest_declaration(
            &self,
            file: &ProjectFile,
            start_byte: usize,
            end_byte: usize,
            ident: &str,
        ) -> Option<brokk_bifrost_analysis::analyzer::DeclarationInfo>;
    }

    fn search_symbol_candidates(
        &self,
        patterns: &brokk_bifrost_analysis::analyzer::i_analyzer::SearchSymbolPatternBatch,
        cancellation: Option<&brokk_bifrost_core::cancellation::CancellationToken>,
    ) -> brokk_bifrost_analysis::analyzer::i_analyzer::SearchSymbolCandidates {
        self.inner.search_symbol_candidates(patterns, cancellation)
    }

    brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::delegate_inner_methods! {
        fn contains_tests(&self, file: &ProjectFile) -> bool;
    }

    fn in_test_region(&self, code_unit: &brokk_bifrost_core::analyzer::model::CodeUnit) -> bool {
        self.inner.in_test_region(code_unit)
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
        detect_language_structural_clone_smells(self, files, weights, Language::Ruby, |code_unit| {
            build_ruby_clone_candidate_data(self, code_unit, weights)
        })
    }

    fn find_test_assertion_smells(
        &self,
        file: &ProjectFile,
        weights: TestAssertionWeights,
    ) -> Vec<TestAssertionSmell> {
        brokk_bifrost_analysis::analyzer::test_assertion_smells_for_file(
            self,
            file,
            Language::Ruby,
            |source| {
                brokk_bifrost_ruby::test_detection::detect_ruby_test_assertion_smells(
                    file, source, &weights,
                )
            },
        )
    }

    fn find_test_assertion_smells_limited(
        &self,
        file: &ProjectFile,
        weights: TestAssertionWeights,
        max_candidates: usize,
    ) -> TestAssertionAnalysis {
        let Some(source) =
            brokk_bifrost_analysis::analyzer::test_assertion_source(self, file, Language::Ruby)
        else {
            return TestAssertionAnalysis {
                findings: Vec::new(),
                inspected_candidates: Some(0),
                truncated: false,
            };
        };
        brokk_bifrost_ruby::test_detection::detect_ruby_test_assertion_smells_limited(
            file,
            &source,
            &weights,
            max_candidates,
        )
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

#[cfg(any(test, feature = "test-support"))]
impl brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerTestHooks for RubyAnalyzer {
    brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::delegate_inner_test_hook_methods! {
        fn reset_relational_definition_batch_call_count_for_test(&self);
    }

    brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::delegate_inner_test_hook_methods! {
        fn relational_definition_batch_call_count_for_test(&self) -> usize;
    }

    brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::delegate_inner_test_hook_methods! {
        fn reset_definition_candidates_query_count_for_test(&self);
    }

    brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::delegate_inner_test_hook_methods! {
        fn definition_candidates_query_count_for_test(&self) -> usize;
    }

    brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::delegate_inner_test_hook_methods! {
        fn reset_definition_prefetch_batch_count_for_test(&self);
    }

    brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::delegate_inner_test_hook_methods! {
        fn definition_prefetch_batch_count_for_test(&self) -> usize;
    }

    brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::delegate_inner_test_hook_methods! {
        fn reset_full_declaration_scan_count_for_test(&self);
    }

    brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::delegate_inner_test_hook_methods! {
        fn full_declaration_scan_count_for_test(&self) -> usize;
    }

    fn reset_candidate_hydration_count_for_test(&self) {
        self.inner.reset_full_hydration_count_for_test();
    }

    brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::delegate_inner_test_hook_methods! {
        fn full_candidate_hydration_count_for_test(&self) -> usize;
    }

    brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::delegate_inner_test_hook_methods! {
        fn bulk_candidate_hydration_count_for_test(&self) -> usize;
    }
}

static RUBY_USAGE_STRATEGY: RubyUsageGraphStrategy = RubyUsageGraphStrategy::new();

#[doc(hidden)]
pub struct RubySupport;

impl LanguageSupport for RubySupport {
    fn workspace_semantic_diagnostics(
        &self,
        workspace: &brokk_bifrost_analysis::analyzer::multi_analyzer::MultiAnalyzer,
        _token: brokk_bifrost_core::analyzer::query_token::QueryToken<'_>,
        file: &ProjectFile,
        source: &str,
    ) -> Option<brokk_bifrost_core::analyzer::model::SemanticDiagnosticReport> {
        // Ruby classifies a constant that leaves the visible require closure
        // against the activated exact gem API packs (#1624), and both the
        // semantic-model overlay and the retained Gemfile.lock discovery
        // evidence belong to the dispatching analyzer, not to the delegate.
        // Passing `workspace` is what lets a gem's indexed constant resolve instead
        // of reporting an unknown boundary.
        Some(diagnostics::collect_ruby_semantic_diagnostics(
            workspace, file, source,
        ))
    }

    fn knowledge(
        &self,
    ) -> &'static dyn brokk_bifrost_core::analyzer::language_knowledge::LanguageKnowledge {
        &brokk_bifrost_ruby::RubyKnowledge
    }

    fn build_analyzer(
        &self,
        project: Arc<dyn brokk_bifrost_core::analyzer::project::Project>,
        config: brokk_bifrost_core::analyzer::config::AnalyzerConfig,
        store_context: brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::AnalyzerStoreContext,
        progress: Option<brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::BuildProgress>,
    ) -> Result<
        brokk_bifrost_analysis::analyzer::multi_analyzer::AnalyzerDelegate,
        brokk_bifrost_analysis::analyzer::store::StoreError,
    > {
        Ok(
            brokk_bifrost_analysis::analyzer::multi_analyzer::AnalyzerDelegate::new(
                RubyAnalyzer::new_with_config_store_context(
                    project,
                    config,
                    store_context,
                    progress,
                )?,
            ),
        )
    }

    fn procedure_syntax_roles(
        &self,
    ) -> Option<brokk_bifrost_analysis::analyzer::languages::ProcedureSyntaxRoles> {
        Some(semantic::PROCEDURE_SYNTAX_ROLES)
    }

    fn type_flow_adapter(
        &self,
    ) -> Option<&'static dyn brokk_bifrost_analysis::analyzer::semantic::type_flow::TypeFlowAdapter>
    {
        Some(&type_flow::RubyTypeFlowAdapter)
    }

    fn signature_metadata_limited(
        &self,
        analyzer: &dyn IAnalyzer,
        unit: &CodeUnit,
        limit: usize,
    ) -> Option<LimitedQueryRows<SignatureMetadata>> {
        resolve_analyzer::<RubyAnalyzer>(analyzer)
            .map(|ruby| ruby.signature_metadata_limited(unit, limit))
    }

    fn signatures_limited(
        &self,
        analyzer: &dyn IAnalyzer,
        unit: &CodeUnit,
        limit: usize,
    ) -> Option<LimitedQueryRows<String>> {
        resolve_analyzer::<RubyAnalyzer>(analyzer).map(|ruby| ruby.signatures_limited(unit, limit))
    }

    fn declaration_ranges_limited(
        &self,
        analyzer: &dyn IAnalyzer,
        unit: &CodeUnit,
        limit: usize,
    ) -> Option<LimitedQueryRows<Range>> {
        brokk_bifrost_analysis::analyzer::languages::with_resolved_analyzer::<RubyAnalyzer, _>(
            analyzer,
            |ruby| ruby.ranges_limited(unit, limit),
        )
    }

    fn forward_query_provider<'a>(
        &self,
        analyzer: &'a dyn IAnalyzer,
    ) -> Option<&'a dyn ForwardQueryProvider> {
        brokk_bifrost_analysis::analyzer::multi_analyzer::forward_query_provider::<RubyAnalyzer>(
            analyzer,
        )
    }

    fn ecosystem(&self) -> UsageEcosystem {
        UsageEcosystem::Ruby
    }

    fn dependency_pack_resolver(
        &self,
    ) -> Option<&'static dyn brokk_bifrost_analysis::analyzer::semantic_model::dependency::DependencyResolver>{
        Some(&dependency_packs::RubyDependencyResolver)
    }

    fn reference_usage_strategy(
        &self,
    ) -> &'static dyn brokk_bifrost_analysis::analyzer::usages::traits::GraphUsageAnalyzer {
        &RUBY_USAGE_STRATEGY
    }

    fn reference_graph_backend(
        &self,
    ) -> brokk_bifrost_analysis::analyzer::languages::LanguageGraphBackend {
        brokk_bifrost_analysis::analyzer::languages::LanguageGraphBackend::Legacy(&RubyEdgePass)
    }

    fn definition_site_for_focus(
        &self,
        site: brokk_bifrost_core::analyzer::usages::reference_site::ResolvedReferenceSite,
        tree: &tree_sitter::Tree,
        source: &str,
        _start: Option<usize>,
        _end: Option<usize>,
    ) -> brokk_bifrost_core::analyzer::usages::reference_site::ResolvedReferenceSite {
        crate::analyzer::usages::get_definition::ruby::ruby_site_for_focus(site, tree, source)
    }

    #[allow(clippy::too_many_arguments)]
    fn resolve_definition_dispatch<'a>(
        &self,
        analyzer: &'a dyn brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer,
        token: brokk_bifrost_core::analyzer::query_token::QueryToken<'_>,
        context: &mut brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionBatchContext<'a, '_>,
        request: &brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionLookupRequest,
        source: &std::sync::Arc<str>,
        tree: &Option<tree_sitter::Tree>,
        site: &brokk_bifrost_core::analyzer::usages::reference_site::ResolvedReferenceSite,
        operation: Option<brokk_bifrost_analysis::navigation::NavigationOperation>,
        cancellation: Option<&brokk_bifrost_core::cancellation::CancellationToken>,
        go_session: Option<
            &brokk_bifrost_core::analyzer::usages::resolution_session::ResolutionSession,
        >,
    ) -> std::ops::ControlFlow<
        brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionResolution,
        brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionResolution,
    > {
        crate::analyzer::usages::get_definition::ruby::resolve_definition_dispatch(
            analyzer,
            token,
            context,
            request,
            source,
            tree,
            site,
            operation,
            cancellation,
            go_session,
        )
    }

    fn definition_call_reference_candidate(&self, node: tree_sitter::Node<'_>) -> bool {
        crate::analyzer::usages::get_definition::ruby::ruby_call_reference_candidate(node)
    }

    fn definition_boundary_evidence(
        &self,
        analyzer: &dyn brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer,
        _token: brokk_bifrost_core::analyzer::query_token::QueryToken<'_>,
        _file: &brokk_bifrost_core::analyzer::model::ProjectFile,
        name: &str,
    ) -> Option<(
        brokk_bifrost_core::analyzer::structural::resolution::BoundaryStatus,
        Option<String>,
    )> {
        use brokk_bifrost_core::analyzer::model::Language;

        use brokk_bifrost_core::analyzer::structural::resolution::BoundaryStatus;
        Some((|| {
            // A Ruby boundary reference is a `::`-joined constant path, and
            // `ruby::constant_identity` is the one resolver that turns such a
            // path into a gem-pack declaration identity, shared with Ruby's
            // proof-gated diagnostics so both classify one path identically. A
            // constant path is *not* a require path, so retained gem evidence
            // is consulted only through the shared verdict helper: a truncated
            // discovery keeps the name accountable, while gem names are never
            // inflected into constant names.
            let overlay = analyzer.semantic_model_overlay();
            let constants = crate::analyzer::ruby::constant_identity::RubyOverlayConstants::new(
                overlay.as_deref(),
            );
            if let Some(symbol) = constants.unique_type(name) {
                return (BoundaryStatus::ExternalIndexed, Some(symbol.id.clone()));
            }
            // Two activated packs claiming one path is still an indexed name;
            // no single target can be reported.
            if constants.conflicts(name) {
                return (BoundaryStatus::ExternalIndexed, None);
            }
            if brokk_bifrost_analysis::analyzer::usages::get_definition::trace::declared_by_retained_discovery(
                analyzer,
                Language::Ruby,
                name,
            ) {
                (BoundaryStatus::ExternalDeclaredUnindexed, None)
            } else {
                (BoundaryStatus::ExternalUnknown, None)
            }
        })())
    }

    fn candidate_augmentation(&self, ctx: &CandidateCtx<'_>) -> Option<CandidateAugmentation> {
        let ruby = resolve_analyzer::<RubyAnalyzer>(ctx.analyzer)?;
        let identifier =
            brokk_bifrost_analysis::analyzer::common::source_identifier_for_target(ctx.target);
        let mut candidates = ruby.reference_candidates_for_identifier(identifier, ctx.cancellation);
        candidates.insert(ctx.target.source().clone());
        Some(CandidateAugmentation::protected(candidates))
    }

    fn dead_code(&self) -> DeadCodeSupport {
        DeadCodeSupport {
            strategy: Some(&RUBY_USAGE_STRATEGY),
            bulk: Some(&RubyDeadCodeBulk),
        }
    }

    fn structural_receiver(&self) -> Option<&'static dyn StructuralReceiverResolver> {
        Some(&RubySupport)
    }
}

struct RubyEdgePass;

impl LanguageEdgePass for RubyEdgePass {
    fn id(&self) -> EdgePassId {
        EdgePassId::Ruby
    }

    fn edge_sites(&self, ctx: &EdgeSiteScanCtx<'_>) -> Option<LanguageEdgeSites> {
        build_rooted_ruby_usage_edges(ctx.analyzer, ctx.fqns, ctx.keep_file)
            .map(LanguageEdgeSites::Fqn)
    }

    fn edge_weights(&self, ctx: &EdgeWeightScanCtx<'_>) -> Option<LanguageEdgeWeights> {
        build_ruby_usage_edge_weights(ctx.analyzer, ctx.fqns, ctx.keep_file)
            .map(LanguageEdgeWeights::Fqn)
    }
}

impl StructuralReceiverResolver for RubySupport {
    fn resolve_type_bounded(
        &self,
        query: BoundedReceiverQuery<'_>,
    ) -> BoundedResolution<TypeLookupOutcome> {
        resolve_ruby_type_bounded(
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
        resolve_ruby_bounded(
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

struct RubyDeadCodeBulk;

impl DeadCodeBulkProof for RubyDeadCodeBulk {
    fn id(&self) -> EdgePassId {
        EdgePassId::Ruby
    }

    /// Only fields are held back: a Ruby attribute's readers and writers are synthesized
    /// rather than called by name, so the inverted pass cannot see their uses.
    fn needs_precise_scan(&self, routing: DeadCodeRouting<'_>) -> bool {
        routing.candidate.is_field()
    }

    fn preflight(&self, analyzer: &dyn IAnalyzer) -> DeadCodeBulkPreflight {
        if resolve_analyzer::<RubyAnalyzer>(analyzer)
            .is_none_or(|ruby| !ruby.canonical_sources_ready())
        {
            return DeadCodeBulkPreflight::Unavailable(
                "canonical Ruby source facts are unavailable",
            );
        }
        DeadCodeBulkPreflight::Ready {
            label: "Ruby",
            files: analyzable_file_count(analyzer, Language::Ruby),
        }
    }

    fn build(
        &self,
        analyzer: &dyn IAnalyzer,
        candidates: &[CodeUnit],
    ) -> Option<DeadCodeBulkEdges> {
        build_fqn_bulk_edges(
            analyzer,
            Language::Ruby,
            candidates,
            |analyzer, nodes, _kinds| build_ruby_usage_edges(analyzer, nodes, |_| true),
        )
    }
}

impl brokk_bifrost_analysis::analyzer::multi_analyzer::LanguageAnalyzer for RubyAnalyzer {
    fn analyzer(&self) -> &dyn IAnalyzer {
        self
    }

    fn program_semantics_provider(
        &self,
    ) -> &dyn brokk_bifrost_analysis::analyzer::semantic::provider::ProgramSemanticsProvider {
        self
    }

    fn clone_with_project(
        &self,
        project: Arc<dyn Project>,
    ) -> Box<dyn brokk_bifrost_analysis::analyzer::multi_analyzer::LanguageAnalyzer> {
        Box::new(RubyAnalyzer::clone_with_project(self, project))
    }

    fn clone_for_index_warm(
        &self,
        project: Arc<dyn Project>,
    ) -> Box<dyn brokk_bifrost_analysis::analyzer::multi_analyzer::LanguageAnalyzer> {
        Box::new(RubyAnalyzer::clone_with_project(self, project))
    }

    fn import_analysis_provider(&self) -> Option<&dyn ImportAnalysisProvider> {
        Some(self)
    }

    fn type_hierarchy_provider(&self) -> Option<&dyn TypeHierarchyProvider> {
        Some(self)
    }

    fn type_alias_provider(
        &self,
    ) -> Option<&dyn brokk_bifrost_core::analyzer::capabilities::TypeAliasProvider> {
        IAnalyzer::type_alias_provider(self)
    }

    fn test_detection_provider(&self) -> Option<&dyn TestDetectionProvider> {
        Some(self)
    }

    fn update(
        &self,
        changed_files: &BTreeSet<ProjectFile>,
    ) -> Box<dyn brokk_bifrost_analysis::analyzer::multi_analyzer::LanguageAnalyzer> {
        Box::new(IAnalyzer::update(self, changed_files))
    }

    fn update_all_with_progress(
        &self,
        progress: Option<BuildProgress>,
    ) -> Box<dyn brokk_bifrost_analysis::analyzer::multi_analyzer::LanguageAnalyzer> {
        Box::new(RubyAnalyzer::update_all_with_progress(self, progress))
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn clone_box(
        &self,
    ) -> Box<dyn brokk_bifrost_analysis::analyzer::multi_analyzer::LanguageAnalyzer> {
        Box::new(Clone::clone(self))
    }
}

mod dependency_packs {

    use brokk_bifrost_analysis::analyzer::semantic_model::dependency::DependencyDiscoveryOutcome;

    use brokk_bifrost_analysis::analyzer::semantic_model::dependency::DependencyPackAdapter;

    use brokk_bifrost_analysis::analyzer::semantic_model::dependency::DependencyPackLimits;

    use brokk_bifrost_analysis::analyzer::semantic_model::dependency::DependencyResolver;

    use brokk_bifrost_analysis::analyzer::semantic_model::dependency::DependencyResolverBounds;

    use brokk_bifrost_analysis::analyzer::workspace::READS_FILES_ONLY;

    use brokk_bifrost_core::analyzer::config::AnalyzerConfig;

    use brokk_bifrost_core::analyzer::project::Project;

    use crate::analyzer::RubyDependencyPackAdapter;

    use crate::analyzer::resolve_ruby_semantic_pack_dependencies;
    pub(crate) struct RubyDependencyResolver;

    impl DependencyResolver for RubyDependencyResolver {
        fn adapter(&self) -> &'static dyn DependencyPackAdapter {
            &RubyDependencyPackAdapter
        }

        fn dependency_inputs(&self) -> &'static [&'static str] {
            &["Gemfile", "Gemfile.lock", "gems.locked"]
        }

        fn bounds(&self, _config: &AnalyzerConfig) -> DependencyResolverBounds {
            READS_FILES_ONLY
        }

        fn resolve(
            &self,
            config: &AnalyzerConfig,
            project: &dyn Project,
            limits: &DependencyPackLimits,
            cancellation: Option<&brokk_bifrost_core::cancellation::CancellationToken>,
        ) -> DependencyDiscoveryOutcome {
            resolve_ruby_semantic_pack_dependencies(&config.ruby, project, limits, cancellation)
        }
    }
}

impl brokk_bifrost_analysis::analyzer::store::StoreLanguageSupport for RubySupport {}
