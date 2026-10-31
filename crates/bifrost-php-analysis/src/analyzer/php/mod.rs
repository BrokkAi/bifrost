//! The analysis-side shim over [`brokk_bifrost_php`].
//!
//! PHP's language knowledge -- the declaration walk, namespace and `use`-alias
//! resolution, composer PSR-4 visibility, the structural spec, test detection,
//! clone normalization and the R1 free functions -- lives in the crate. What
//! stays here is the [`PhpAnalyzer`] struct with its one moka cache, one
//! `PoolSafeMemo` and the `Arc<PhpComposerAutoload>` it rebuilds when
//! `composer.json` changes, the `PhpAdapter` forwarding shell, the core
//! capability impls the crate resolves through, the `LanguageSupport` SPI block,
//! and the executable-semantics lowerer.

use brokk_bifrost_analysis::analyzer::read_ledger::ReadKey;
use brokk_bifrost_analysis::analyzer::read_ledger::WorkspaceFactFamily;
use brokk_bifrost_analysis::analyzer::store::cache_budget::{RetainedHeap, retained_read_key};
use brokk_bifrost_analysis::analyzer::workspace_authority::{
    AuthorityInputs, WorkspaceAuthorityMemo, record_workspace_authority_read,
};
use brokk_bifrost_analysis::analyzer::workspace_authority::{
    ReplayingMemo, ReplayingMemoEntry, memo_attribution,
};
use brokk_bifrost_analysis::{
    delegate_inner_methods, delegate_inner_procedure_fact_methods,
    forward_file_identity_invalidation, forward_relational_definition_batch,
    impl_forward_query_provider,
};
use brokk_bifrost_core::analyzer::capabilities::HierarchyAnswer;
#[doc(hidden)]
pub mod adapter;
mod clones;
pub mod dependency_discovery;
pub(crate) mod diagnostics;
mod external;
mod imports;
mod semantic;
mod source_artifact;
pub(crate) mod source_publication;
#[doc(hidden)]
pub mod source_storage;
mod structural;
mod type_flow;

pub use crate::analyzer::php::dependency_discovery::PHP_MAX_AUTOLOAD_RULES_PER_PACKAGE;

pub use crate::analyzer::php::dependency_discovery::resolve_php_semantic_pack_dependencies;

pub use crate::analyzer::php::external::ComposerPackagePackProducer;

pub use crate::analyzer::php::external::ComposerPinnedAutoloadRule;

pub use crate::analyzer::php::external::PhpDeclarationStubPackProducer;

pub use crate::analyzer::php::external::PhpDependencyPackAdapter;

pub use crate::analyzer::php::semantic::php_declared_scalar_types;

use brokk_bifrost_analysis::analyzer::clone_detection::detect_language_structural_clone_smells;

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

use brokk_bifrost_analysis::analyzer::languages::build_fqn_bulk_edges;

use brokk_bifrost_analysis::analyzer::languages::ready_preflight;

use crate::analyzer::php::source_storage::CanonicalPhpSourceFacts;

use brokk_bifrost_core::analyzer::query_batch::LimitedQueryRows;

use brokk_bifrost_analysis::analyzer::usages::common::analyzed_files_for_language;

use brokk_bifrost_core::analyzer::usages::resolution_session::BoundedResolution;

use brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionLookupOutcome;

use crate::analyzer::usages::get_definition::php::resolve_php_bounded;

use brokk_bifrost_analysis::analyzer::usages::get_type::TypeLookupOutcome;

use crate::analyzer::usages::get_type::resolve_php_type_bounded;

use crate::analyzer::usages::php_graph::PhpDeadCodeBulkEligibility;

use crate::analyzer::usages::php_graph::PhpUsageGraphStrategy;

use crate::analyzer::usages::php_graph::build_php_usage_edge_weights;

use crate::analyzer::usages::php_graph::build_php_usage_edges;

use crate::analyzer::usages::php_graph::build_rooted_php_usage_edges;

use crate::analyzer::usages::php_graph::dead_code_bulk_eligibility;

use brokk_bifrost_analysis::analyzer::usages::workspace_graph::UsageEcosystem;

use brokk_bifrost_core::analyzer::weighted_cache::build_weighted_cache;

use brokk_bifrost_core::analyzer::config::AnalyzerConfig;

use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::AnalyzerStoreContext;

use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::BuildProgress;

use brokk_bifrost_core::analyzer::model::CodeUnit;

use brokk_bifrost_core::analyzer::capabilities::DescendantIndexScope;

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

use brokk_bifrost_core::analyzer::model::SignatureMetadata;

use brokk_bifrost_core::analyzer::model::TestAssertionSmell;

use brokk_bifrost_core::analyzer::model::TestAssertionWeights;

use brokk_bifrost_core::analyzer::capabilities::TestDetectionProvider;

use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::TreeSitterAnalyzer;

use brokk_bifrost_core::analyzer::capabilities::TypeHierarchyProvider;

use brokk_bifrost_analysis::analyzer::workspace::WorkspaceAnalyzer;

use brokk_bifrost_core::analyzer::capabilities::build_direct_descendant_index;

use brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer;

use brokk_bifrost_core::hash::HashMap;

use brokk_bifrost_core::hash::HashSet;

use brokk_bifrost_core::analyzer::model::CloneSmell;

use brokk_bifrost_core::analyzer::model::CloneSmellWeights;
use moka::sync::Cache;
use std::collections::BTreeSet;
use std::sync::Arc;

pub(crate) use crate::analyzer::php::adapter::PhpAdapter;

#[doc(hidden)]
pub use crate::analyzer::php::source_artifact::PHP_GLOBAL_NAMESPACE;

pub(crate) fn resolve_php_analyzer(workspace: &WorkspaceAnalyzer) -> Option<&PhpAnalyzer> {
    resolve_analyzer::<PhpAnalyzer>(workspace.analyzer())
}
// The parked bounded-definition route (`usages/get_definition/php.rs`) resolves
// these through the module, so the chain now runs crate -> shim -> parked file
// rather than the other way around.

// Public aliases come from the PHP knowledge crate and are re-exported by
// this crate's analyzer facade.
pub use brokk_bifrost_php::aliases::{
    PhpUseAliases, parse_php_use_aliases, parse_php_use_aliases_by_kind,
    parse_php_use_aliases_from_source, php_namespace_to_fq,
};
use brokk_bifrost_php::composer::PhpComposerAutoload;
use brokk_bifrost_php::graph_support::{
    php_import_alias_candidates, php_is_constructor, php_namespace_of_file,
    php_resolve_declared_supertype, php_use_aliases_by_kind_of, php_use_aliases_of,
};
pub use brokk_bifrost_php::structural::{PhpCallResultUseIndex, php_call_result_use};
use brokk_bifrost_php::test_detection::detect_php_test_assertion_smells;

use crate::analyzer::php::clones::build_php_clone_candidate_data;

type ReverseImports = HashMap<ProjectFile, Arc<HashSet<ProjectFile>>>;

type MemoEntry<T> = Arc<ReplayingMemoEntry<T, ReadKey>>;
type BoundedMemo<K, V> = Arc<ReplayingMemo<Cache<K, MemoEntry<V>>>>;

#[derive(Clone)]
pub struct PhpAnalyzer {
    inner: TreeSitterAnalyzer<PhpAdapter>,
    memo_budget: u64,
    source_facts: Cache<
        (
            brokk_bifrost_analysis::analyzer::store::GenerationId,
            brokk_bifrost_core::gitblob::BlobKey,
            ProjectFile,
        ),
        Arc<brokk_bifrost_php::source_facts::PhpFileSourceFacts>,
    >,
    direct_ancestors: BoundedMemo<CodeUnit, Arc<Vec<CodeUnit>>>,
    /// `PoolSafeMemo`, not `OnceLock`: this whole-workspace build is reached
    /// from rayon workers during cold scans, and a blocking `get_or_init` parks
    /// every one of them behind the single initializer for its full duration.
    /// Keyed by [`DescendantIndexVariant`]: a request that excluded test files
    /// gets an index that was never built over them (issue #1748). Two cells at
    /// most, because the exclusion verdict is a pure function of the analyzer
    /// and the file.
    direct_descendant_index: Arc<
        WorkspaceAuthorityMemo<KeyedPoolSafeMemo<DescendantIndexVariant, DirectDescendantIndex>>,
    >,
    /// The declarations of other files that one file's persisted import names
    /// resolve to, keyed by file because the persisted names are. An entry
    /// depends on the whole workspace's declarations, not only on its own
    /// file's blob, so both cells are built fresh by `update` rather than
    /// invalidated per changed file -- the same lifetime `direct_ancestors`
    /// has.
    imported_code_units: BoundedMemo<ProjectFile, Arc<HashSet<CodeUnit>>>,
    /// Which files import each file, inverted from `imported_code_units` over
    /// the whole workspace in one pass.
    reverse_import_index: Arc<WorkspaceAuthorityMemo<PoolSafeMemo<ReverseImports>>>,
    composer_autoload: Arc<PhpComposerAutoload>,
}

impl_forward_query_provider!(PhpAnalyzer);

impl brokk_bifrost_php::source_facts::PhpSourceFactProvider for PhpAnalyzer {
    fn php_source_facts_while(
        &self,
        file: &ProjectFile,
        keep_going: &dyn Fn() -> bool,
    ) -> Option<Arc<brokk_bifrost_php::source_facts::PhpFileSourceFacts>> {
        self.inner
            .canonical_php_source_facts(file, &self.source_facts, keep_going)
    }
}

impl PhpAnalyzer {
    fn authority_inputs(&self) -> AuthorityInputs<'static> {
        let Some(key) =
            brokk_bifrost_analysis::analyzer::workspace_authority::workspace_authority_file_input(
                self,
                Language::Php,
                "composer.json",
            )
        else {
            return AuthorityInputs::Unnamed;
        };
        AuthorityInputs::SourceAndFiles {
            languages: &[Language::Php],
            files: Arc::from([key]),
        }
    }

    pub(crate) fn update_all_with_progress(
        &self,
        progress: Option<brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::BuildProgress>,
    ) -> Self {
        brokk_bifrost_core::analyzer::project_reads::without_project_reads(|| {
            Self::from_inner(
                self.inner.update_all_with_progress(progress),
                self.memo_budget,
            )
        })
    }

    pub(crate) fn clone_with_project(&self, project: Arc<dyn Project>) -> Self {
        let mut clone = self.clone();
        clone.inner = clone.inner.clone_with_project(project);
        clone
    }

    pub fn new(project: Arc<dyn Project>) -> Self {
        Self::new_with_config(project, AnalyzerConfig::default())
    }

    pub fn new_with_config(project: Arc<dyn Project>, config: AnalyzerConfig) -> Self {
        TreeSitterAnalyzer::wrap_with_config(
            config,
            |config| TreeSitterAnalyzer::new_with_config(project, PhpAdapter, config),
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
                    PhpAdapter,
                    config,
                    store_context,
                    progress,
                )
            },
            Self::from_inner,
        )
    }

    fn from_inner(inner: TreeSitterAnalyzer<PhpAdapter>, memo_budget: u64) -> Self {
        let composer_autoload = Arc::new(PhpComposerAutoload::from_project(inner.project()));
        Self::from_inner_with_composer(inner, memo_budget, composer_autoload)
    }

    fn from_inner_with_composer(
        inner: TreeSitterAnalyzer<PhpAdapter>,
        memo_budget: u64,
        composer_autoload: Arc<PhpComposerAutoload>,
    ) -> Self {
        Self {
            inner,
            memo_budget,
            source_facts: build_weighted_cache(
                memo_budget / 8,
                |_key, facts: &Arc<brokk_bifrost_php::source_facts::PhpFileSourceFacts>| {
                    u32::try_from(facts.estimated_retained_bytes())
                        .unwrap_or(u32::MAX)
                        .max(1)
                },
            ),
            direct_ancestors: Arc::new(ReplayingMemo::new(build_weighted_cache(
                memo_budget / 8,
                |_key, entry: &MemoEntry<Arc<Vec<CodeUnit>>>| {
                    u32::try_from(entry.retained_bytes(|key| {
                        let mut heap = RetainedHeap::default();
                        retained_read_key(&mut heap, key);
                        heap.total()
                    }))
                    .unwrap_or(u32::MAX)
                    .max(1)
                },
            ))),
            direct_descendant_index: Arc::new(WorkspaceAuthorityMemo::new(
                WorkspaceFactFamily::PhpDirectDescendants,
                KeyedPoolSafeMemo::new(),
            )),
            imported_code_units: Arc::new(ReplayingMemo::new(build_weighted_cache(
                memo_budget / 8,
                |_key, entry: &MemoEntry<Arc<HashSet<CodeUnit>>>| {
                    u32::try_from(entry.retained_bytes(|key| {
                        let mut heap = RetainedHeap::default();
                        retained_read_key(&mut heap, key);
                        heap.total()
                    }))
                    .unwrap_or(u32::MAX)
                    .max(1)
                },
            ))),
            reverse_import_index: Arc::new(WorkspaceAuthorityMemo::new(
                WorkspaceFactFamily::PhpReverseImports,
                PoolSafeMemo::new(),
            )),
            composer_autoload,
        }
    }

    pub fn from_project<P>(project: P) -> Self
    where
        P: Project + 'static,
    {
        Self::new(Arc::new(project))
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
        let Some(identifier) = fqn.rsplit('.').next().filter(|name| !name.is_empty()) else {
            return LimitedQueryRows::complete(Vec::new(), 0);
        };
        // PHP names are intrinsic to source contents, but the adapter predates
        // persisted FQN lookup keys. Query the bounded identifier index, then
        // retain only the exact analyzer identity; this is still an exact
        // lookup and never falls back to a same-name declaration.
        let mut candidates =
            self.inner
                .lookup_declarations_by_identifier_limited(identifier, limit, continue_query);
        candidates.rows.retain(|unit| unit.fq_name() == fqn);
        candidates
    }

    delegate_inner_methods! {
        pub(crate) fn direct_children_limited(
        &self,
        owner: &CodeUnit,
        limit: usize,
    ) -> LimitedQueryRows<CodeUnit>;
    }

    delegate_inner_methods! {
        pub(crate) fn signature_metadata_limited(
        &self,
        code_unit: &CodeUnit,
        limit: usize,
    ) -> LimitedQueryRows<SignatureMetadata>;
    }

    delegate_inner_methods! {
        pub(crate) fn signatures_limited(
        &self,
        code_unit: &CodeUnit,
        limit: usize,
    ) -> LimitedQueryRows<String>;
    }

    delegate_inner_methods! {
        #[doc(hidden)]
        pub fn reset_full_hydration_count_for_test(&self);
    }

    delegate_inner_methods! {
        #[doc(hidden)]
        pub fn full_hydration_count_for_test(&self) -> usize;
    }

    pub(crate) fn ranges_limited(
        &self,
        code_unit: &CodeUnit,
        limit: usize,
    ) -> LimitedQueryRows<Range> {
        self.inner.ranges_limited(code_unit, limit)
    }

    pub fn is_constructor(
        &self,
        method: &CodeUnit,
        class_unit: &CodeUnit,
        package_name: &str,
    ) -> bool {
        php_is_constructor(method, class_unit, package_name)
    }

    pub fn namespace_of_file(&self, file: &ProjectFile) -> String {
        php_namespace_of_file(self, file)
    }

    pub fn use_aliases_of(&self, file: &ProjectFile) -> HashMap<String, String> {
        php_use_aliases_of(self, file)
    }

    pub fn use_aliases_by_kind_of(&self, file: &ProjectFile) -> PhpUseAliases {
        php_use_aliases_by_kind_of(self, file)
    }

    pub(crate) fn target_has_composer_autoload_visibility(&self, target: &CodeUnit) -> bool {
        if brokk_bifrost_analysis::analyzer::read_attribution_records_reads(|| {
            self.read_ledger_attached()
        }) {
            record_workspace_authority_read(
                self,
                WorkspaceFactFamily::PhpComposerAutoload,
                self.authority_inputs(),
            );
        }
        self.composer_autoload.target_is_autoloaded(self, target)
    }
}

impl TestDetectionProvider for PhpAnalyzer {}

impl TypeHierarchyProvider for PhpAnalyzer {
    fn get_direct_ancestors(&self, code_unit: &CodeUnit) -> HierarchyAnswer {
        let ancestors = self.direct_ancestors.read(&memo_attribution(self), |cache, capture| {
            Ok::<_, std::convert::Infallible>(cache.get(code_unit).unwrap_or_else(|| {
                let cache_fill =
                    brokk_bifrost_analysis::analyzer::common::QueryCacheFill::new(self);
                let entry = Arc::new(capture.build_weighted(|| {
                    let ancestors: Vec<CodeUnit> = self.inner.raw_supertypes_of(code_unit).iter()
                            .filter_map(|raw| php_resolve_declared_supertype(self, code_unit, raw)).collect();
                    let ancestors = Arc::new(ancestors);
                    let bytes = brokk_bifrost_core::analyzer::weighted_cache::weight_code_unit_vec_by_unit(code_unit, &ancestors) as usize;
                    (ancestors, bytes)
                }));
                if cache_fill.is_complete() {
                cache.insert(code_unit.clone(), Arc::clone(&entry));
                }
                entry
            }))
        }).expect("ancestor memo build is infallible");
        HierarchyAnswer::complete((**ancestors).clone())
    }

    fn get_direct_descendants(&self, code_unit: &CodeUnit) -> HierarchyAnswer {
        let cancellation = brokk_bifrost_core::cancellation::CancellationToken::default();
        self.get_direct_descendants_within(
            code_unit,
            &DescendantIndexScope::whole_workspace(&cancellation),
        )
        .expect("a whole-workspace descendant query cannot be cancelled")
    }

    fn get_direct_descendants_within(
        &self,
        code_unit: &CodeUnit,
        scope: &DescendantIndexScope<'_>,
    ) -> Result<HierarchyAnswer, brokk_bifrost_core::analyzer::capabilities::Cancelled> {
        self.direct_descendant_index.read(
            &memo_attribution(self),
            |memo| {
                brokk_bifrost_analysis::analyzer::common::complete_descendant_query(
                    self,
                    scope,
                    code_unit,
                    memo,
                    || build_direct_descendant_index(self, self, scope),
                    |_| {},
                )
            },
            |_| AuthorityInputs::SourceOf(&[Language::Php]),
        )
    }
}

use brokk_bifrost_core::analyzer::code_unit_index::CodeUnitIndex;

impl CodeUnitIndex for PhpAnalyzer {
    delegate_inner_methods! {
        /// Forwarded so the request-scoped memo on the inner analyzer answers
        /// (#2679); the trait default would rebuild uncached per call.
        fn class_range_index(
        &self,
        file: &ProjectFile,
    ) -> std::sync::Arc<brokk_bifrost_core::analyzer::usages::inverted_edges::ClassRangeIndex>;
    }

    fn enclosing_code_unit(&self, file: &ProjectFile, range: &Range) -> Option<CodeUnit> {
        self.inner.enclosing_code_unit(file, range)
    }

    delegate_inner_methods! {
        fn enclosing_code_unit_for_lines(
            &self,
            file: &ProjectFile,
            start_line: usize,
            end_line: usize,
        ) -> Option<CodeUnit>;
    }

    delegate_inner_methods! {
        fn top_level_declarations(&self, file: &ProjectFile) -> Vec<CodeUnit>;
    }

    delegate_inner_methods! {
        fn summary_file_projection(
        &self,
        file: &ProjectFile,
    ) -> Option<Arc<brokk_bifrost_analysis::analyzer::SummaryFileProjection>>;
    }

    delegate_inner_methods! {
        fn analyzed_files(&self) -> Vec<ProjectFile>;
    }

    delegate_inner_methods! {
        fn indexed_source(&self, file: &ProjectFile) -> Option<String>;
    }

    delegate_inner_methods! {
        fn indexed_blob_oid(&self, file: &ProjectFile) -> Option<brokk_bifrost_analysis::analyzer::Oid>;
    }

    delegate_inner_methods! {
        fn location_declarations(&self, file: &ProjectFile) -> BTreeSet<CodeUnit>;
    }

    delegate_inner_methods! {
        fn location_ranges(&self, code_unit: &CodeUnit) -> Vec<brokk_bifrost_analysis::analyzer::Range>;
    }

    delegate_inner_methods! {
        fn indexed_source_matches(&self, file: &ProjectFile, source: &str) -> bool;
    }

    delegate_inner_methods! {
        fn is_analyzed(&self, file: &ProjectFile) -> bool;
    }

    delegate_inner_methods! {
        fn retain_analyzed(&self, candidates: &[ProjectFile]) -> Vec<ProjectFile>;
    }

    fn all_declarations(&self) -> Box<dyn Iterator<Item = CodeUnit> + '_> {
        self.inner.all_declarations()
    }

    delegate_inner_methods! {
        fn declarations_sharing_name(&self, unit: &CodeUnit) -> Vec<CodeUnit>;
    }

    delegate_inner_methods! {
        fn declarations(&self, file: &ProjectFile) -> BTreeSet<CodeUnit>;
    }

    fn definitions(&self, fq_name: &str) -> Box<dyn Iterator<Item = CodeUnit> + '_> {
        self.inner.definitions(fq_name)
    }

    delegate_inner_methods! {
        fn direct_children(&self, code_unit: &CodeUnit) -> Vec<CodeUnit>;
    }

    delegate_inner_methods! {
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

    delegate_inner_methods! {
        fn signature_metadata(&self, code_unit: &CodeUnit) -> Vec<SignatureMetadata>;
    }

    delegate_inner_methods! {
        fn languages(&self) -> BTreeSet<Language>;
    }

    delegate_inner_methods! {
        fn project(&self) -> &dyn Project;
    }

    delegate_inner_methods! {
        fn get_all_declarations(&self) -> Vec<CodeUnit>;
    }

    fn get_skeleton(&self, code_unit: &CodeUnit) -> Option<String> {
        let skeleton = self.inner.get_skeleton(code_unit)?;
        if code_unit.is_class() && self.inner.direct_children(code_unit).is_empty() {
            let trimmed = skeleton.trim();
            if trimmed.ends_with("{\n}") || trimmed.ends_with("{\r\n}") {
                let compact = trimmed.trim_end_matches('}').trim_end().to_string();
                return Some(format!("{compact} }}"));
            }
        }
        Some(skeleton)
    }

    delegate_inner_methods! {
        fn get_skeleton_header(&self, code_unit: &CodeUnit) -> Option<String>;
    }

    delegate_inner_methods! {
        fn get_source(&self, code_unit: &CodeUnit, include_comments: bool) -> Option<String>;
    }

    delegate_inner_methods! {
        fn get_sources(&self, code_unit: &CodeUnit, include_comments: bool) -> BTreeSet<String>;
    }

    delegate_inner_methods! {
        fn search_definitions(&self, pattern: &str, auto_quote: bool) -> BTreeSet<CodeUnit>;
    }

    delegate_inner_methods! {
        fn search_definitions_by_suffix_pattern(
        &self,
        pattern: &str,
        terminal_identifiers: &[String],
        language: Language,
    ) -> BTreeSet<CodeUnit>;
    }

    delegate_inner_methods! {
        fn lookup_candidates_by_short_name(&self, symbol: &str) -> BTreeSet<CodeUnit>;
    }

    delegate_inner_methods! {
        fn has_complete_symbol_lookup_index(&self) -> bool;
    }

    fn lookup_candidates_by_identifier(&self, identifier: &str) -> BTreeSet<CodeUnit> {
        self.inner.lookup_declarations_by_identifier(identifier)
    }
}

impl IAnalyzer for PhpAnalyzer {
    brokk_bifrost_analysis::forward_query_read_ledger!();

    delegate_inner_procedure_fact_methods!();

    forward_relational_definition_batch!();

    forward_file_identity_invalidation!();

    fn working_tree_identity(
        &self,
    ) -> Option<std::sync::Arc<brokk_bifrost_core::gitblob::WorkingTreeIdentity>> {
        self.inner.working_tree_identity()
    }

    #[cfg(any(test, feature = "test-support"))]
    fn test_hooks(&self) -> &dyn brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerTestHooks {
        self
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

    delegate_inner_methods! {
        fn prefetch_definitions(&self, fq_names: &[String]);
    }

    delegate_inner_methods! {
        fn record_query_failure(&self, error: brokk_bifrost_analysis::analyzer::store::StoreError);
    }

    delegate_inner_methods! {
        fn workspace_file_index_cell(&self) -> Option<brokk_bifrost_analysis::analyzer::WorkspaceFileIndexCell>;
    }

    delegate_inner_methods! {
        fn definition_lookup_memo(
        &self,
    ) -> Option<std::sync::Arc<brokk_bifrost_analysis::analyzer::DefinitionLookupMemo>>;
    }

    delegate_inner_methods! {
        fn structural_fact_providers(
        &self,
    ) -> Vec<&dyn brokk_bifrost_analysis::analyzer::structural::StructuralFactProvider>;
    }

    fn snapshot_caches(
        &self,
    ) -> Option<&brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerSnapshotCaches> {
        Some(self.inner.snapshot_caches())
    }

    delegate_inner_methods! {
        fn workspace_content_identities(
        &self,
    ) -> Option<brokk_bifrost_analysis::analyzer::content_identity::WorkspaceContentIdentities>;
    }

    delegate_inner_methods! {
        fn workspace_fact_indexes(
        &self,
    ) -> Vec<&dyn brokk_bifrost_analysis::analyzer::read_verification::WorkspaceFactIndex>;
    }

    delegate_inner_methods! {
        fn import_statements(&self, file: &ProjectFile) -> Vec<String>;
    }

    delegate_inner_methods! {
        fn compute_cognitive_complexities(&self, file: &ProjectFile) -> Vec<(CodeUnit, u32)>;
    }

    fn update(&self, changed_files: &BTreeSet<ProjectFile>) -> Self {
        brokk_bifrost_core::analyzer::project_reads::without_project_reads(|| {
            let inner = self.inner.update(changed_files);
            let composer_autoload = if changed_files
                .iter()
                .any(PhpComposerAutoload::manifest_changed)
            {
                Arc::new(PhpComposerAutoload::from_project(inner.project()))
            } else {
                self.composer_autoload.clone()
            };
            Self::from_inner_with_composer(inner, self.memo_budget, composer_autoload)
        })
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
        // The collector now states its own proof for every reference, so the
        // blanket workspace-local wrapper would overstate what it checked.
        diagnostics::collect_php_semantic_diagnostics(self, file, source)
    }

    delegate_inner_methods! {
        fn extract_call_receiver(&self, reference: &str) -> Option<String>;
    }

    delegate_inner_methods! {
        fn is_access_expression(&self, file: &ProjectFile, start_byte: usize, end_byte: usize) -> bool;
    }

    delegate_inner_methods! {
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

    fn type_hierarchy_provider(&self) -> Option<&dyn TypeHierarchyProvider> {
        Some(self)
    }

    fn import_analysis_provider(&self) -> Option<&dyn ImportAnalysisProvider> {
        Some(self)
    }

    delegate_inner_methods! {
        fn contains_tests(&self, file: &ProjectFile) -> bool;
    }

    fn in_test_region(&self, code_unit: &brokk_bifrost_core::analyzer::model::CodeUnit) -> bool {
        self.inner.in_test_region(code_unit)
    }

    fn find_test_assertion_smells(
        &self,
        file: &ProjectFile,
        weights: TestAssertionWeights,
    ) -> Vec<TestAssertionSmell> {
        brokk_bifrost_analysis::analyzer::test_assertion_smells_for_file(
            self,
            file,
            Language::Php,
            |source| detect_php_test_assertion_smells(file, source, &weights),
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
        detect_language_structural_clone_smells(self, files, weights, Language::Php, |code_unit| {
            build_php_clone_candidate_data(self, code_unit, weights)
        })
    }

    fn test_detection_provider(&self) -> Option<&dyn TestDetectionProvider> {
        Some(self)
    }
}

#[cfg(any(test, feature = "test-support"))]
impl brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerTestHooks for PhpAnalyzer {
    brokk_bifrost_analysis::delegate_inner_test_hook_methods! {
        fn reset_relational_definition_batch_call_count_for_test(&self);
    }

    brokk_bifrost_analysis::delegate_inner_test_hook_methods! {
        fn relational_definition_batch_call_count_for_test(&self) -> usize;
    }

    brokk_bifrost_analysis::delegate_inner_test_hook_methods! {
        fn reset_definition_candidates_query_count_for_test(&self);
    }

    brokk_bifrost_analysis::delegate_inner_test_hook_methods! {
        fn definition_candidates_query_count_for_test(&self) -> usize;
    }

    brokk_bifrost_analysis::delegate_inner_test_hook_methods! {
        fn reset_definition_prefetch_batch_count_for_test(&self);
    }

    brokk_bifrost_analysis::delegate_inner_test_hook_methods! {
        fn definition_prefetch_batch_count_for_test(&self) -> usize;
    }

    brokk_bifrost_analysis::delegate_inner_test_hook_methods! {
        fn reset_full_declaration_scan_count_for_test(&self);
    }

    brokk_bifrost_analysis::delegate_inner_test_hook_methods! {
        fn full_declaration_scan_count_for_test(&self) -> usize;
    }

    fn reset_candidate_hydration_count_for_test(&self) {
        self.inner.reset_full_hydration_count_for_test();
    }

    brokk_bifrost_analysis::delegate_inner_test_hook_methods! {
        fn full_candidate_hydration_count_for_test(&self) -> usize;
    }

    brokk_bifrost_analysis::delegate_inner_test_hook_methods! {
        fn bulk_candidate_hydration_count_for_test(&self) -> usize;
    }
}

static PHP_USAGE_STRATEGY: PhpUsageGraphStrategy = PhpUsageGraphStrategy::new();

#[doc(hidden)]
pub struct PhpSupport;

impl LanguageSupport for PhpSupport {
    fn workspace_semantic_diagnostics(
        &self,
        workspace: &brokk_bifrost_analysis::analyzer::multi_analyzer::MultiAnalyzer,
        _token: brokk_bifrost_core::analyzer::query_token::QueryToken<'_>,
        file: &ProjectFile,
        source: &str,
    ) -> Option<brokk_bifrost_core::analyzer::model::SemanticDiagnosticReport> {
        // PHP's proof ladder reads the semantic-model overlay and the retained
        // Composer discovery evidence, and only the dispatching analyzer holds
        // them. Delegating to the `PhpAnalyzer` would hand the collector a view
        // with no indexed dependencies, so every vendor symbol would look
        // unknown even with an active pack.
        Some(diagnostics::collect_php_semantic_diagnostics(
            workspace, file, source,
        ))
    }

    fn knowledge(
        &self,
    ) -> &'static dyn brokk_bifrost_core::analyzer::language_knowledge::LanguageKnowledge {
        &brokk_bifrost_php::PhpKnowledge
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
                PhpAnalyzer::new_with_config_store_context(
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

    fn signature_metadata_limited(
        &self,
        analyzer: &dyn IAnalyzer,
        unit: &CodeUnit,
        limit: usize,
    ) -> Option<LimitedQueryRows<SignatureMetadata>> {
        resolve_analyzer::<PhpAnalyzer>(analyzer)
            .map(|php| php.signature_metadata_limited(unit, limit))
    }

    fn signatures_limited(
        &self,
        analyzer: &dyn IAnalyzer,
        unit: &CodeUnit,
        limit: usize,
    ) -> Option<LimitedQueryRows<String>> {
        resolve_analyzer::<PhpAnalyzer>(analyzer).map(|php| php.signatures_limited(unit, limit))
    }

    fn declaration_ranges_limited(
        &self,
        analyzer: &dyn IAnalyzer,
        unit: &CodeUnit,
        limit: usize,
    ) -> Option<LimitedQueryRows<Range>> {
        resolve_analyzer::<PhpAnalyzer>(analyzer).map(|php| php.ranges_limited(unit, limit))
    }

    fn forward_query_provider<'a>(
        &self,
        analyzer: &'a dyn IAnalyzer,
    ) -> Option<&'a dyn ForwardQueryProvider> {
        brokk_bifrost_analysis::analyzer::multi_analyzer::forward_query_provider::<PhpAnalyzer>(
            analyzer,
        )
    }

    fn ecosystem(&self) -> UsageEcosystem {
        UsageEcosystem::Php
    }

    fn dependency_pack_resolver(
        &self,
    ) -> Option<&'static dyn brokk_bifrost_analysis::analyzer::semantic_model::dependency::DependencyResolver>{
        Some(&dependency_packs::ComposerDependencyResolver)
    }

    fn reference_usage_strategy(
        &self,
    ) -> &'static dyn brokk_bifrost_analysis::analyzer::usages::traits::GraphUsageAnalyzer {
        &PHP_USAGE_STRATEGY
    }

    fn reference_graph_backend(
        &self,
    ) -> brokk_bifrost_analysis::analyzer::languages::LanguageGraphBackend {
        brokk_bifrost_analysis::analyzer::languages::LanguageGraphBackend::Legacy(&PhpEdgePass)
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
        crate::analyzer::usages::get_definition::php::resolve_definition_dispatch(
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
        crate::analyzer::usages::get_definition::php::php_call_reference_candidate(node)
    }

    fn dead_code(&self) -> DeadCodeSupport {
        DeadCodeSupport {
            strategy: Some(&PHP_USAGE_STRATEGY),
            bulk: Some(&PhpDeadCodeBulk),
        }
    }

    fn structural_receiver(&self) -> Option<&'static dyn StructuralReceiverResolver> {
        Some(&PhpSupport)
    }

    fn type_flow_adapter(
        &self,
    ) -> Option<&'static dyn brokk_bifrost_analysis::analyzer::semantic::type_flow::TypeFlowAdapter>
    {
        Some(&type_flow::PhpTypeFlowAdapter)
    }

    /// Both expansions are supplemental. Composer autoload visibility means any analyzed
    /// PHP file may reference the target, so the expansion is the whole language's file
    /// set -- accurate but unbounded, and worth dropping the moment a budget bites rather
    /// than displacing the import-graph candidates that are far likelier to hold a usage.
    fn candidate_augmentation(&self, ctx: &CandidateCtx<'_>) -> Option<CandidateAugmentation> {
        let php = resolve_analyzer::<PhpAnalyzer>(ctx.analyzer)?;
        let analyzed_php_files = || analyzed_files_for_language(ctx.analyzer, Language::Php);
        let mut files = HashSet::default();
        if php.target_has_composer_autoload_visibility(ctx.target) {
            files.extend(analyzed_php_files());
        }
        match php_import_alias_candidates(
            ctx.target,
            ctx.analyzer,
            ctx.analyzer.type_hierarchy_provider(),
            php,
            &analyzed_php_files,
        ) {
            Ok(aliases) => files.extend(aliases),
            Err(_) => {
                brokk_bifrost_analysis::analyzer::record_descendant_query_failure(ctx.analyzer)
            }
        }
        Some(CandidateAugmentation::supplemental(files))
    }
}

struct PhpEdgePass;

impl LanguageEdgePass for PhpEdgePass {
    fn id(&self) -> EdgePassId {
        EdgePassId::Php
    }

    fn edge_sites(&self, ctx: &EdgeSiteScanCtx<'_>) -> Option<LanguageEdgeSites> {
        build_rooted_php_usage_edges(ctx.analyzer, ctx.fqns, ctx.keep_file)
            .map(LanguageEdgeSites::Fqn)
    }

    fn edge_weights(&self, ctx: &EdgeWeightScanCtx<'_>) -> Option<LanguageEdgeWeights> {
        build_php_usage_edge_weights(ctx.analyzer, ctx.fqns, ctx.declaration_kinds, ctx.keep_file)
            .map(LanguageEdgeWeights::Fqn)
    }
}

impl StructuralReceiverResolver for PhpSupport {
    fn resolve_type_bounded(
        &self,
        query: BoundedReceiverQuery<'_>,
    ) -> BoundedResolution<TypeLookupOutcome> {
        resolve_php_type_bounded(
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
        resolve_php_bounded(
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

struct PhpDeadCodeBulk;

impl DeadCodeBulkProof for PhpDeadCodeBulk {
    fn id(&self) -> EdgePassId {
        EdgePassId::Php
    }

    fn needs_precise_scan(&self, routing: DeadCodeRouting<'_>) -> bool {
        matches!(
            dead_code_bulk_eligibility(routing.analyzer, routing.candidate),
            PhpDeadCodeBulkEligibility::NeedsPrecise
        )
    }

    fn preflight(&self, analyzer: &dyn IAnalyzer) -> DeadCodeBulkPreflight {
        ready_preflight(analyzer, Language::Php, "PHP")
    }

    fn build(
        &self,
        analyzer: &dyn IAnalyzer,
        candidates: &[CodeUnit],
    ) -> Option<DeadCodeBulkEdges> {
        build_fqn_bulk_edges(
            analyzer,
            Language::Php,
            candidates,
            |analyzer, nodes, kinds| build_php_usage_edges(analyzer, nodes, kinds, |_| true),
        )
    }
}

mod dependency_packs {

    use brokk_bifrost_analysis::analyzer::semantic_model::DependencyDiscoveryOutcome;

    use brokk_bifrost_analysis::analyzer::semantic_model::DependencyPackAdapter;

    use brokk_bifrost_analysis::analyzer::semantic_model::DependencyPackLimits;

    use brokk_bifrost_analysis::analyzer::semantic_model::dependency::DependencyResolver;

    use brokk_bifrost_analysis::analyzer::semantic_model::DependencyResolverBounds;

    use brokk_bifrost_analysis::analyzer::workspace::READS_FILES_ONLY;

    use brokk_bifrost_core::analyzer::config::AnalyzerConfig;

    use brokk_bifrost_core::analyzer::project::Project;
    pub(crate) struct ComposerDependencyResolver;

    impl DependencyResolver for ComposerDependencyResolver {
        fn adapter(&self) -> &'static dyn DependencyPackAdapter {
            &crate::analyzer::php::PhpDependencyPackAdapter
        }

        fn dependency_inputs(&self) -> &'static [&'static str] {
            &["composer.json", "composer.lock", "installed.json"]
        }

        fn bounds(&self, _config: &AnalyzerConfig) -> DependencyResolverBounds {
            READS_FILES_ONLY
        }

        fn adjust_limits(&self, _config: &AnalyzerConfig, limits: &mut DependencyPackLimits) {
            // Composer emits one artifact per autoload rule so a PSR-4 prefix stays
            // bound to the files it admits. Discovery caps the rule count itself,
            // so the artifact budget only has to admit that cap.
            limits.max_artifacts_per_dependency = limits
                .max_artifacts_per_dependency
                .max(crate::analyzer::php::PHP_MAX_AUTOLOAD_RULES_PER_PACKAGE);
        }

        fn resolve(
            &self,
            config: &AnalyzerConfig,
            project: &dyn Project,
            limits: &DependencyPackLimits,
            cancellation: Option<&brokk_bifrost_core::cancellation::CancellationToken>,
        ) -> DependencyDiscoveryOutcome {
            crate::analyzer::php::resolve_php_semantic_pack_dependencies(
                &config.php,
                project,
                limits,
                cancellation,
            )
        }
    }
}

impl brokk_bifrost_analysis::analyzer::store::StoreLanguageSupport for PhpSupport {}

#[cfg(test)]
mod source_fact_tests;

impl brokk_bifrost_analysis::analyzer::multi_analyzer::LanguageAnalyzer for PhpAnalyzer {
    fn analyzer(&self) -> &dyn IAnalyzer {
        self
    }

    fn program_semantics_provider(
        &self,
    ) -> &dyn brokk_bifrost_analysis::analyzer::semantic::ProgramSemanticsProvider {
        self
    }

    fn clone_with_project(
        &self,
        project: Arc<dyn Project>,
    ) -> Box<dyn brokk_bifrost_analysis::analyzer::multi_analyzer::LanguageAnalyzer> {
        Box::new(PhpAnalyzer::clone_with_project(self, project))
    }

    fn clone_for_index_warm(
        &self,
        project: Arc<dyn Project>,
    ) -> Box<dyn brokk_bifrost_analysis::analyzer::multi_analyzer::LanguageAnalyzer> {
        Box::new(PhpAnalyzer::clone_with_project(self, project))
    }

    fn import_analysis_provider(&self) -> Option<&dyn ImportAnalysisProvider> {
        IAnalyzer::import_analysis_provider(self)
    }

    fn type_hierarchy_provider(&self) -> Option<&dyn TypeHierarchyProvider> {
        IAnalyzer::type_hierarchy_provider(self)
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
        Box::new(PhpAnalyzer::update_all_with_progress(self, progress))
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

#[cfg(test)]
mod acquisition_tests;

#[cfg(test)]
mod memo_read_tests {
    use super::*;
    use brokk_bifrost_analysis::analyzer::capture_query_reads;
    use brokk_bifrost_analysis::test_support::AnalyzerFixture;
    use brokk_bifrost_php::source_facts::PhpSourceFactProvider;

    #[test]
    #[brokk_bifrost_test_macros::hardwon("#2445: PHP wrapper dropped workspace authority reads")]
    fn composer_visibility_records_absent_manifest_inputs() {
        let fixture = AnalyzerFixture::new_for_language(
            Language::Php,
            &[("service.php", "<?php class Service {}")],
        );
        let analyzer = PhpAnalyzer::from_project(fixture.test_project().clone());
        let class = analyzer
            .all_declarations()
            .find(CodeUnit::is_class)
            .unwrap();
        assert!(!analyzer.target_has_composer_autoload_visibility(&class));
        let (visible, reads) = capture_query_reads(&analyzer, || {
            analyzer.target_has_composer_autoload_visibility(&class)
        });
        assert!(!visible);
        assert!(reads.keys().iter().any(|key| matches!(key, ReadKey::PathAbsent { rel_path, .. } if rel_path.as_ref() == "composer.json")), "{:?}", reads.keys());
        assert_eq!(reads.unattributed_reads(), 0);
    }

    #[test]
    fn cached_source_facts_record_the_file_input() {
        let fixture = AnalyzerFixture::new_for_language(
            Language::Php,
            &[("service.php", "<?php class Service {}")],
        );
        let analyzer = PhpAnalyzer::from_project(fixture.test_project().clone());
        let file = ProjectFile::new(analyzer.project().root().to_path_buf(), "service.php");
        assert!(analyzer.php_source_facts_while(&file, &|| true).is_some());
        let (facts, reads) = capture_query_reads(&analyzer, || {
            analyzer.php_source_facts_while(&file, &|| true)
        });
        assert!(facts.is_some());
        assert!(reads.keys().iter().any(|key| matches!(key, ReadKey::File { language: Language::Php, rel_path, .. } if rel_path.as_ref() == "service.php")));
        assert_eq!(reads.unattributed_reads(), 0);
    }
}
