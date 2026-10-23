//! The analyzer-owned shim over [`brokk_bifrost_python`].
//!
//! What lives here is everything the language crate cannot name: the
//! [`PythonAnalyzer`] newtype and its seven moka caches and four
//! `PoolSafeMemo`s; the accessors that implement
//! [`brokk_bifrost_python::graph_support::PythonSource`] and
//! [`brokk_bifrost_python::graph_support::PythonUsageSource`] out of them; the
//! `PythonAdapter` forwarding shell; the `IAnalyzer`/`CodeUnitIndex` impls; and
//! the `LanguageSupport` SPI block.

#[doc(hidden)]
pub mod adapter;
mod cache;
mod clones;
mod default_arguments;
pub(crate) mod diagnostics;
mod exception_identity;
pub mod external;
mod guard_summary;
mod hierarchy;
mod imports;
pub(crate) mod lexical_scope;
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub mod native_environment;
pub mod packaging;
pub mod runtime_artifact;
pub(crate) mod runtime_binding;
pub(crate) mod runtime_environment;
pub(crate) mod runtime_provider;
mod semantic;
pub(crate) mod source_publication;
#[doc(hidden)]
pub mod source_storage;
mod structural;
mod type_flow;

use brokk_bifrost_core::analyzer::query_token::QueryToken;

use brokk_bifrost_core::analyzer::model::Range;

use crate::analyzer::python::source_storage::CanonicalPythonSourceFacts;

pub(crate) use crate::analyzer::python::type_flow::python_attribute_value_terminal_range;

pub(crate) use crate::analyzer::python::type_flow::python_exact_external_receiver_identities;

pub(crate) use crate::analyzer::python::type_flow::python_external_class_call_identity;

#[doc(hidden)]
pub use crate::analyzer::python::type_flow::python_external_member_declaration;

pub(crate) use crate::analyzer::python::type_flow::python_external_value_member_on_workspace_class;

use brokk_bifrost_analysis::analyzer::cache_weight::weight_code_unit_vec;

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

use brokk_bifrost_analysis::analyzer::languages::ExternalCalleeSite;

use brokk_bifrost_analysis::analyzer::languages::ImportedExternalCallee;

use brokk_bifrost_analysis::analyzer::languages::LanguageEdgePass;

use brokk_bifrost_analysis::analyzer::languages::LanguageEdgeSites;

use brokk_bifrost_analysis::analyzer::languages::LanguageEdgeWeights;

use brokk_bifrost_analysis::analyzer::languages::LanguageSupport;

use brokk_bifrost_analysis::analyzer::languages::SavedDefaultArgumentSafety;

use brokk_bifrost_analysis::analyzer::languages::StructuralReceiverResolver;

use brokk_bifrost_analysis::analyzer::languages::candidate_fqns;

use brokk_bifrost_analysis::analyzer::languages::fqn_bulk_nodes;

use brokk_bifrost_analysis::analyzer::languages::ready_preflight;

use brokk_bifrost_core::analyzer::query_batch::LimitedQueryRows;

use brokk_bifrost_core::analyzer::usages::resolution_session::BoundedResolution;

use brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionLookupOutcome;

use brokk_bifrost_core::analyzer::usages::resolution_session::ResolutionSession;

use crate::analyzer::usages::get_definition::python::PythonDefinitionProvider;

use crate::analyzer::usages::get_definition::python::python_external_imported_symbol_bounded;

use crate::analyzer::usages::get_definition::python::resolve_python_bounded;

use brokk_bifrost_analysis::analyzer::usages::get_type::TypeLookupOutcome;

use brokk_bifrost_analysis::analyzer::usages::get_type::TypeLookupStatus;

use crate::analyzer::usages::get_type::resolve_python_type_bounded;

use crate::analyzer::usages::python_graph::PythonExportUsageGraphStrategy;

use crate::analyzer::usages::python_graph::build_cached_python_usage_edges_for_targets;

use crate::analyzer::usages::python_graph::build_python_usage_edge_weights;

use crate::analyzer::usages::python_graph::python_usage_candidate_files;

use brokk_bifrost_core::analyzer::usages::receiver_analysis::INTERACTIVE_TYPE_LOOKUP_BUDGET;

use brokk_bifrost_core::analyzer::usages::reference_site::ResolvedReferenceSite;

use brokk_bifrost_analysis::analyzer::usages::workspace_graph::UsageEcosystem;

use brokk_bifrost_core::analyzer::usages::model::ExportIndex;

use brokk_bifrost_core::analyzer::usages::model::ImportBinder;

use brokk_bifrost_core::analyzer::weighted_cache::build_weighted_cache;

use brokk_bifrost_core::analyzer::weighted_cache::weight_code_unit_set;

use brokk_bifrost_core::analyzer::weighted_cache::weight_export_index;

use brokk_bifrost_core::analyzer::weighted_cache::weight_project_file_set;

use brokk_bifrost_core::analyzer::config::AnalyzerConfig;

use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::AnalyzerStoreContext;

use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::BuildProgress;

use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::BulkFileStateSource;

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

use brokk_bifrost_core::analyzer::model::SignatureMetadata;

use brokk_bifrost_core::analyzer::model::TestAssertionSmell;

use brokk_bifrost_core::analyzer::model::TestAssertionWeights;

use brokk_bifrost_core::analyzer::capabilities::TestDetectionProvider;

use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::TreeSitterAnalyzer;

use brokk_bifrost_core::analyzer::capabilities::TypeHierarchyProvider;

use brokk_bifrost_core::analyzer::capabilities::build_reverse_import_index;

use brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer;

use brokk_bifrost_core::hash::HashMap;

use brokk_bifrost_core::hash::HashSet;

use brokk_bifrost_core::analyzer::common::node_source_text;
use brokk_bifrost_core::analyzer::prepared_syntax::IndexedFileFacts;
use brokk_bifrost_core::profiling;
use brokk_bifrost_python::imports::{
    PythonImportDetails, python_assignment_chain, python_import_details,
    python_import_infos_from_node,
};
use brokk_bifrost_python::syntax::{python_plain_string_literal, python_static_attribute_path};
use moka::sync::Cache;
use std::collections::BTreeSet;
use std::sync::Arc;

use brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope;

use brokk_bifrost_core::analyzer::query_token::QueryScope;

#[doc(hidden)]
pub use crate::analyzer::python::adapter::PythonAdapter;
use brokk_bifrost_python::declarations::python_expanded_comment_start;
use brokk_bifrost_python::graph_support::{
    PythonModuleSpellings, PythonSource, PythonUsageSource, compute_export_index_of,
    import_binder_from_imports, render_skeleton_recursive,
};
use brokk_bifrost_python::imports::resolve_imports_batched;
use brokk_bifrost_python::source_facts::PythonSourceFactProvider;
use brokk_bifrost_python::test_detection::detect_python_test_assertion_smells;
use brokk_bifrost_python::usage_index::PythonUsageIndex;

use crate::analyzer::python::cache::PythonClassMutationKey;

use crate::analyzer::python::cache::PythonModuleMemberMutationKey;

use crate::analyzer::python::cache::PythonUsageEdgesKey;

use crate::analyzer::python::cache::build_python_class_mutation_cache;

use crate::analyzer::python::cache::build_python_module_member_mutation_cache;

use crate::analyzer::python::cache::weight_import_binder;

use crate::analyzer::python::cache::weight_module_global_source_facts;

use crate::analyzer::python::cache::weight_python_usage_edges;

use crate::analyzer::python::clones::build_clone_candidate_data;

pub use crate::analyzer::python::exception_identity::python_builtin_exception_is_subclass;

pub use crate::analyzer::python::exception_identity::python_builtin_exception_name;

pub use brokk_bifrost_python::imports::{
    PythonImportBinding, parse_python_import_bindings, parse_python_import_infos,
};

const FILE_STATE_BATCH_SIZE: usize = 256;

#[derive(Clone)]
pub struct PythonAnalyzer {
    inner: TreeSitterAnalyzer<PythonAdapter>,
    memo_budget: u64,
    imported_code_units: Cache<ProjectFile, Arc<HashSet<CodeUnit>>>,
    source_facts: Cache<
        (
            brokk_bifrost_analysis::analyzer::store::GenerationId,
            git2::Oid,
            ProjectFile,
        ),
        Arc<brokk_bifrost_python::source_facts::PythonFileSourceFacts>,
    >,
    module_global_source_facts: Cache<
        (
            brokk_bifrost_analysis::analyzer::store::GenerationId,
            git2::Oid,
            ProjectFile,
        ),
        Arc<brokk_bifrost_python::source_facts::PythonModuleGlobalSourceFacts>,
    >,
    // Every source file this file's imports resolve to, keyed on the file itself -- NOT deduped by
    // binding name like `imported_code_units` (a HashMap<String, CodeUnit> would silently drop an
    // import whose binding name collides with another's). `could_import_file` needs the undeduped
    // set to answer "does ANY import here resolve into `target`" without re-resolving every import
    // on every call (previously uncached, called once per (candidate file, target) pair).
    imported_target_files: Cache<ProjectFile, Arc<HashSet<ProjectFile>>>,
    referencing_files: Cache<ProjectFile, Arc<HashSet<ProjectFile>>>,
    // Re-export resolution memoizes the source-owned import/order projection
    // once per file and analyzer generation, including unsaved overlays.
    export_index: Cache<ProjectFile, Arc<ExportIndex>>,
    // Uncached, this rebuilt the whole per-file binding map -- including a store lookup per
    // from-import through `resolve_module_code_unit` -- for every single `.bindings.get(name)` the
    // receiver-type and annotation resolvers do. One binder per file serves all of them.
    import_binder: Cache<ProjectFile, Arc<ImportBinder>>,
    direct_ancestors: Cache<CodeUnit, Arc<Vec<CodeUnit>>>,
    // Dead-code analysis scans the stable caller domain but resolves a bounded
    // callee target set. Cache that exact pair for warm requests so repeated
    // queries do not reparse the entire Python workspace.
    usage_edges: Cache<
        PythonUsageEdgesKey,
        Arc<brokk_bifrost_core::analyzer::usages::inverted_edges::UsageEdges>,
    >,
    class_member_mutation_free: Cache<PythonClassMutationKey, bool>,
    module_member_mutation_free: Cache<PythonModuleMemberMutationKey, bool>,
    // PoolSafeMemo, not OnceLock: same constraint as `usage_index` below. The
    // build walks every workspace class and is reached from rayon workers, so a
    // blocking get_or_init parks each arriving worker behind one initializer.
    /// Keyed by [`DescendantIndexVariant`]: a request that excluded test files
    /// gets an index that was never built over them (issue #1748). Two cells at
    /// most, because the exclusion verdict is a pure function of the analyzer
    /// and the file.
    direct_descendant_index: Arc<KeyedPoolSafeMemo<DescendantIndexVariant, DirectDescendantIndex>>,
    reverse_import_index: Arc<PoolSafeMemo<HashMap<ProjectFile, Arc<HashSet<ProjectFile>>>>>,
    // PoolSafeMemo, not OnceLock: this cell is reached from inside rayon workers -- the graph
    // extractor's per-file fan-out resolves module bindings through it. The builder is serial, so
    // the same closure serves both memo arms; what the memo buys is the non-blocking claim
    // protocol, which stops a cold whole-workspace build from parking every worker that arrives
    // behind the one thread running the initializer.
    usage_index: Arc<PoolSafeMemo<PythonUsageIndex>>,
    // PoolSafeMemo for the same reason as `usage_index`: the import resolver
    // reaches this from rayon workers. The build is path math over the
    // workspace listing, but every import that names no indexed module asks
    // for it, so it must not be recomputed per import.
    module_spellings: Arc<PoolSafeMemo<PythonModuleSpellings>>,
    // Share capped per-kind evidence across oracles in this generation (#5112).
    saved_default_arguments: Arc<PoolSafeMemo<SavedDefaultArgumentSafety>>,
}

impl_forward_query_provider!(PythonAnalyzer);

impl PythonAnalyzer {
    pub(crate) fn update_all_with_progress(
        &self,
        progress: Option<brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::BuildProgress>,
    ) -> Self {
        Self::from_inner(
            self.inner.update_all_with_progress(progress),
            self.memo_budget,
        )
    }

    pub(crate) fn install_python_runtime_snapshot(
        &self,
        base: &brokk_bifrost_analysis::analyzer::store::WorkspaceSnapshotId,
        published: brokk_bifrost_analysis::analyzer::store::WorkspaceSnapshotId,
    ) -> Result<(), brokk_bifrost_analysis::analyzer::store::StoreError> {
        self.inner.install_python_runtime_snapshot(base, published)
    }

    pub(crate) fn python_runtime_store_snapshot(
        &self,
    ) -> Option<(
        Arc<brokk_bifrost_analysis::analyzer::store::AnalyzerStore>,
        brokk_bifrost_analysis::analyzer::store::WorkspaceSnapshotId,
    )> {
        let snapshots = self.inner.selected_workspace_snapshots();
        let snapshot = snapshots.get("python")?.clone();
        Some((Arc::clone(self.inner.analyzer_store()), snapshot))
    }

    /// Return one typed memo shared by every nested scope of the active query.
    /// Definition resolution uses this rather than exposing the language
    /// analyzer's complete tree-sitter implementation.
    pub(crate) fn active_query_request_memo<T>(&self) -> Option<Arc<T>>
    where
        T: Default + Send + Sync + 'static,
    {
        self.inner.active_query_request_memo::<T>()
    }

    pub(crate) fn module_candidates_by_fqn_limited(
        &self,
        fqn: &str,
        limit: usize,
        continue_query: impl FnMut() -> bool,
    ) -> LimitedQueryRows<CodeUnit> {
        self.inner
            .lookup_path_modules_by_fqn_limited(fqn, limit, continue_query)
    }

    pub(crate) fn declaration_candidates_by_identifier_limited(
        &self,
        identifier: &str,
        limit: usize,
        continue_query: impl FnMut() -> bool,
    ) -> LimitedQueryRows<CodeUnit> {
        self.inner
            .lookup_non_module_declarations_by_identifier_limited(identifier, limit, continue_query)
    }

    pub(crate) fn declaration_candidates_by_fqn_limited(
        &self,
        fqn: &str,
        limit: usize,
        continue_query: impl FnMut() -> bool,
    ) -> LimitedQueryRows<CodeUnit> {
        self.inner
            .lookup_non_module_declarations_by_fqn_limited(fqn, limit, continue_query)
    }

    /// A Python class body is one contiguous region of one file, so a member
    /// declaration belongs to `owner` only when it is nested in `owner`'s own
    /// file. The qualified name alone is not enough: two sibling source roots
    /// can spell one module, which gives two classes one qualified name
    /// (#3475), and a name-only owner test then hands each class the other's
    /// members and reports the other's fields as absent.
    pub(crate) fn member_candidates_for_owner_limited(
        &self,
        owner: &CodeUnit,
        name: &str,
        limit: usize,
        continue_query: impl FnMut() -> bool,
    ) -> LimitedQueryRows<CodeUnit> {
        let mut candidates = self
            .inner
            .lookup_non_module_declarations_by_identifier_limited(name, limit, continue_query);
        if candidates.complete {
            candidates.rows.retain(|candidate| {
                candidate.source() == owner.source()
                    && candidate
                        .fq()
                        .parent()
                        .is_some_and(|parent| parent == *owner.fq())
            });
        }
        candidates
    }

    pub(crate) fn ranges_limited(
        &self,
        code_unit: &CodeUnit,
        limit: usize,
    ) -> LimitedQueryRows<brokk_bifrost_core::analyzer::model::Range> {
        self.inner.ranges_limited(code_unit, limit)
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

    #[cfg(test)]
    pub(crate) fn prepared_syntax_parse_count_for_test(&self, file: &ProjectFile) -> usize {
        self.inner.prepared_syntax_parse_count_for_test(file)
    }

    #[doc(hidden)]
    pub fn clone_with_project(&self, project: Arc<dyn Project>) -> Self {
        let mut clone = self.clone();
        clone.inner = clone.inner.clone_with_project(project);
        if clone.inner.workspace_configuration_changed() {
            return Self::from_inner(clone.inner.reproject_workspace(), self.memo_budget);
        }
        // Both products describe the snapshot's file view, not just the
        // analyzer's parsed content: the usage index holds the module index
        // and the source-root spelling index the snapshot's own package
        // markers built, and a re-projected analyzer must not answer an
        // overlay with the candidates of the project it was cloned from
        // (#3506). Content-keyed cells stay: a re-projection is a same-root
        // overlay operation, so the files a caller resolves against are the
        // files these were built from.
        clone.module_spellings = Arc::new(PoolSafeMemo::new());
        clone.usage_index = Arc::new(PoolSafeMemo::new());
        clone.usage_edges = build_weighted_cache(self.memo_budget / 8, weight_python_usage_edges);
        clone.class_member_mutation_free = build_python_class_mutation_cache();
        clone.module_member_mutation_free = build_python_module_member_mutation_cache();
        clone.saved_default_arguments = Arc::new(PoolSafeMemo::new());
        clone
    }

    pub fn new(project: Arc<dyn Project>) -> Self {
        Self::new_with_config(project, AnalyzerConfig::default())
    }

    pub fn new_with_config(project: Arc<dyn Project>, config: AnalyzerConfig) -> Self {
        TreeSitterAnalyzer::wrap_with_config(
            config,
            |config| TreeSitterAnalyzer::new_with_config(project, PythonAdapter::default(), config),
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
                    PythonAdapter::default(),
                    config,
                    store_context,
                    progress,
                )
            },
            Self::from_inner,
        )
    }

    fn from_inner(inner: TreeSitterAnalyzer<PythonAdapter>, memo_budget: u64) -> Self {
        Self {
            inner,
            memo_budget,
            imported_code_units: build_weighted_cache(memo_budget / 4, weight_code_unit_set),
            source_facts: build_weighted_cache(
                memo_budget / 8,
                |_, value: &Arc<brokk_bifrost_python::source_facts::PythonFileSourceFacts>| {
                    u32::try_from(value.estimated_retained_bytes()).unwrap_or(u32::MAX)
                },
            ),
            module_global_source_facts: build_weighted_cache(
                memo_budget / 16,
                weight_module_global_source_facts,
            ),
            imported_target_files: build_weighted_cache(memo_budget / 8, weight_project_file_set),
            referencing_files: build_weighted_cache(memo_budget / 8, weight_project_file_set),
            export_index: build_weighted_cache(memo_budget / 8, weight_export_index),
            import_binder: build_weighted_cache(memo_budget / 8, weight_import_binder),
            direct_ancestors: build_weighted_cache(memo_budget / 8, weight_code_unit_vec),
            usage_edges: build_weighted_cache(memo_budget / 8, weight_python_usage_edges),
            class_member_mutation_free: build_python_class_mutation_cache(),
            module_member_mutation_free: build_python_module_member_mutation_cache(),
            direct_descendant_index: Arc::new(KeyedPoolSafeMemo::new()),
            reverse_import_index: Arc::new(PoolSafeMemo::new()),
            usage_index: Arc::new(PoolSafeMemo::new()),
            module_spellings: Arc::new(PoolSafeMemo::new()),
            saved_default_arguments: Arc::new(PoolSafeMemo::new()),
        }
    }

    /// Bounded metadata evidence is scanned once per analyzer generation.
    /// `update` constructs a fresh analyzer with fresh memo cells, so edits
    /// invalidate this evidence without a separate invalidation protocol (#5112).
    pub(crate) fn saved_default_argument_safety(&self) -> Arc<SavedDefaultArgumentSafety> {
        self.saved_default_arguments
            .get_or_build_pool_independent(|| {
                default_arguments::saved_default_argument_safety(self)
            })
    }

    pub fn from_project<P>(project: P) -> Self
    where
        P: Project + 'static,
    {
        Self::new(Arc::new(project))
    }

    pub(crate) fn usage_edges_for_targets(
        &self,
        nodes: &HashSet<String>,
        targets: &HashSet<String>,
        build: impl FnOnce() -> Option<brokk_bifrost_core::analyzer::usages::inverted_edges::UsageEdges>,
    ) -> Option<Arc<brokk_bifrost_core::analyzer::usages::inverted_edges::UsageEdges>> {
        let key = PythonUsageEdgesKey::new(nodes, targets);
        self.usage_edges
            .optionally_get_with(key, || build().map(Arc::new))
    }

    pub(crate) fn cached_class_member_mutation_free(
        &self,
        identity_groups: &[Vec<&str>],
        member: &str,
        scan: impl FnOnce() -> bool,
    ) -> bool {
        self.class_member_mutation_free
            .get_with(PythonClassMutationKey::new(identity_groups, member), scan)
    }

    pub(crate) fn cached_module_member_mutation_free(
        &self,
        module: &str,
        member: &str,
        scan: impl FnOnce() -> Option<bool>,
    ) -> bool {
        self.module_member_mutation_free
            .optionally_get_with(PythonModuleMemberMutationKey::new(module, member), scan)
            .unwrap_or(false)
    }

    pub(crate) fn module_global_source_facts(
        &self,
        file: &ProjectFile,
        prepared: &brokk_bifrost_core::analyzer::prepared_syntax::PreparedSyntaxTree,
        keep_going: &dyn Fn() -> bool,
    ) -> Option<Arc<brokk_bifrost_python::source_facts::PythonModuleGlobalSourceFacts>> {
        self.inner.cached_python_module_global_source_facts(
            file,
            prepared,
            &self.module_global_source_facts,
            keep_going,
        )
    }

    #[doc(hidden)]
    pub fn write_live_file_to_store_for_test(&self, file: &ProjectFile) -> Option<()> {
        self.inner.write_live_file_to_store_for_test(file)
    }

    /// The cached re-export/importer index, built once per analyzer generation.
    fn usage_index(&self, token: QueryToken<'_>) -> Arc<PythonUsageIndex> {
        self.usage_index.get_or_build(
            || PythonUsageIndex::build(self, token),
            || PythonUsageIndex::build(self, token),
        )
    }

    /// Coalesce concurrent first lookups of the same source-owned export facts.
    pub fn export_index_of(&self, token: QueryToken<'_>, file: &ProjectFile) -> Arc<ExportIndex> {
        self.export_index.get_with(file.clone(), || {
            Arc::new(compute_export_index_of(self, token, file))
        })
    }

    /// `get_with` for the same reason as `export_index_of`: the receiver-type and annotation
    /// resolvers ask for this from the parallelized candidate walk.
    pub fn import_binder_of(&self, token: QueryToken<'_>, file: &ProjectFile) -> Arc<ImportBinder> {
        self.import_binder.get_with(file.clone(), || {
            Arc::new(import_binder_from_imports(
                self,
                file,
                &self.inner.import_info_of(token, file),
            ))
        })
    }

    /// The set of files any of `file`'s imports resolve into, cached per file. Unlike
    /// `resolve_import_bindings` (keyed by binding name, so a name collision drops an entry), this
    /// keeps every resolved target so `could_import_file` can do an exact membership check.
    ///
    /// `get_with` (not get-then-insert): `could_import_file` is called concurrently across worker
    /// threads by the now-parallelized candidate walker, and get-then-insert would let two threads
    /// that both miss the cache for the same file each redundantly pay the whole-file resolution
    /// cost. `get_with` guarantees only one thread ever runs the init closure per key.
    fn resolve_import_target_files(
        &self,
        token: QueryToken<'_>,
        file: &ProjectFile,
    ) -> Arc<HashSet<ProjectFile>> {
        brokk_bifrost_analysis::analyzer::common::import_target_files_from_cache(
            &self.imported_target_files,
            file,
            || {
                let imports = self.inner.import_info_of(token, file);
                let targets: HashSet<ProjectFile> = resolve_imports_batched(self, file, &imports)
                    .into_iter()
                    .flatten()
                    .map(|(_, code_unit)| code_unit.source().clone())
                    .collect();
                targets
            },
        )
    }

    fn build_reverse_import_index(&self) -> Arc<HashMap<ProjectFile, Arc<HashSet<ProjectFile>>>> {
        self.reverse_import_index.get_or_build(
            || self.compute_reverse_import_index(true),
            || self.compute_reverse_import_index(false),
        )
    }

    fn compute_reverse_import_index(
        &self,
        parallel: bool,
    ) -> HashMap<ProjectFile, Arc<HashSet<ProjectFile>>> {
        let _scope = profiling::scope("PythonAnalyzer::build_reverse_import_index");
        let files: Vec<_> = self.inner.all_files();
        let reverse =
            build_reverse_import_index(&files, |file| self.imported_code_units_of(file), parallel);

        if profiling::enabled() {
            profiling::note(format!(
                "PythonAnalyzer::build_reverse_import_index files={} indexed_targets={}",
                files.len(),
                reverse.len()
            ));
        }

        reverse
    }
}

impl PythonSourceFactProvider for PythonAnalyzer {
    fn python_source_facts(
        &self,
        _token: QueryToken<'_>,
        file: &ProjectFile,
        keep_going: &dyn Fn() -> bool,
    ) -> Option<Arc<brokk_bifrost_python::source_facts::PythonFileSourceFacts>> {
        self.inner
            .canonical_python_source_facts(file, &self.source_facts, keep_going)
    }
}

use brokk_bifrost_core::analyzer::code_unit_index::CodeUnitIndex;

impl PythonSource for PythonAnalyzer {
    fn path_module_fqn(&self, module_fq: &str) -> Option<Vec<CodeUnit>> {
        self.inner.forward_path_module_fqn(module_fq)
    }

    fn path_module_fqns_batch(&self, module_fqs: &[String]) -> Vec<Option<Vec<CodeUnit>>> {
        self.inner.forward_path_module_fqns_batch(module_fqs)
    }

    fn definition_fqn(&self, fqn: &str) -> Vec<CodeUnit> {
        self.inner.forward_definition_fqn(fqn)
    }

    fn module_spellings(&self) -> Arc<PythonModuleSpellings> {
        // `workspace_language_files`, not the analyzed set: this answers a
        // question about file identity, and a workspace file that has not been
        // parsed yet still has a path-derived module name. The markers are read
        // through the project, so an overlay's unsaved `__path__` statement is
        // the evidence this snapshot's roots rest on (#3506).
        self.module_spellings.get_or_build(
            || {
                PythonModuleSpellings::build(
                    self.inner.workspace_language_files(),
                    self.inner.adapter().shared_project(),
                )
            },
            || {
                PythonModuleSpellings::build(
                    self.inner.workspace_language_files(),
                    self.inner.adapter().shared_project(),
                )
            },
        )
    }

    fn import_binder_of(&self, file: &ProjectFile) -> Arc<ImportBinder> {
        brokk_bifrost_analysis::analyzer::i_analyzer::with_query_scope(self, |token| {
            self.import_binder_of(token, file)
        })
    }

    fn export_index_of(&self, file: &ProjectFile) -> Arc<ExportIndex> {
        let scope = AnalyzerQueryScope::new(self);
        let token = scope.token();
        self.export_index_of(token, file)
    }

    fn prepared_syntax(
        &self,
        token: QueryToken<'_>,
        file: &ProjectFile,
    ) -> Option<Arc<brokk_bifrost_core::analyzer::prepared_syntax::PreparedSyntaxTree>> {
        self.inner.prepared_syntax(token, file)
    }

    fn visit_file_facts(
        &self,
        files: &[ProjectFile],
        visit: &mut dyn FnMut(&ProjectFile, Option<&dyn IndexedFileFacts>),
    ) {
        for batch in files.chunks(FILE_STATE_BATCH_SIZE) {
            let file_states = self
                .inner
                .bulk_file_states(batch.iter().cloned(), BulkFileStateSource::Include);
            for file in batch {
                visit(
                    file,
                    file_states
                        .get(file)
                        .map(|state| state as &dyn IndexedFileFacts),
                );
            }
        }
    }
}

impl PythonUsageSource for PythonAnalyzer {
    fn usage_index(&self) -> Arc<PythonUsageIndex> {
        let scope = AnalyzerQueryScope::new(self);
        let token = scope.token();
        self.usage_index(token)
    }
}

impl CodeUnitIndex for PythonAnalyzer {
    delegate_inner_methods! {
        /// Forwarded so the request-scoped memo on the inner analyzer answers
        /// (#2679); the trait default would rebuild uncached per call.
        fn class_range_index(
        &self,
        file: &ProjectFile,
    ) -> std::sync::Arc<brokk_bifrost_core::analyzer::usages::inverted_edges::ClassRangeIndex>;
    }

    delegate_inner_methods! {
        fn enclosing_code_unit(
        &self,
        file: &ProjectFile,
        range: &brokk_bifrost_analysis::analyzer::Range,
    ) -> Option<CodeUnit>;
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

    fn materialization_records(
        &self,
        file: &ProjectFile,
    ) -> Vec<brokk_bifrost_core::analyzer::structural::materialization::MaterializationRecord> {
        self.inner.materialization_records(file)
    }

    fn definitions(&self, fq_name: &str) -> Box<dyn Iterator<Item = CodeUnit> + '_> {
        self.inner.definitions(fq_name)
    }

    delegate_inner_methods! {
        fn prefetch_definitions(&self, fq_names: &[String]);
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

    fn project(&self) -> &dyn Project {
        self.inner.adapter().project()
    }

    fn parent_of(&self, code_unit: &CodeUnit) -> Option<CodeUnit> {
        self.inner.structural_parent_of(code_unit)
    }

    delegate_inner_methods! {
        fn get_all_declarations(&self) -> Vec<CodeUnit>;
    }

    fn get_skeleton(&self, code_unit: &CodeUnit) -> Option<String> {
        let mut rendered = String::new();
        render_skeleton_recursive(self, code_unit, "", false, &mut rendered);
        brokk_bifrost_analysis::analyzer::common::normalize_skeleton(rendered)
    }

    fn get_skeleton_header(&self, code_unit: &CodeUnit) -> Option<String> {
        let mut rendered = String::new();
        render_skeleton_recursive(self, code_unit, "", true, &mut rendered);
        brokk_bifrost_analysis::analyzer::common::normalize_skeleton(rendered)
    }

    fn get_sources(&self, code_unit: &CodeUnit, include_comments: bool) -> BTreeSet<String> {
        if !include_comments {
            return self.inner.get_sources(code_unit, false);
        }

        let mut ranges = if code_unit.is_function() {
            let mut grouped = Vec::new();
            for candidate in self.inner.definitions(&code_unit.fq_name()) {
                if candidate.source() == code_unit.source() {
                    grouped.extend(self.inner.ranges(&candidate).iter().copied());
                }
            }
            grouped
        } else {
            self.inner.ranges(code_unit).to_vec()
        };

        let Some(source) = self.inner.file_source(code_unit.source()) else {
            return BTreeSet::new();
        };

        ranges.sort_by_key(|range| range.start_byte);
        ranges
            .into_iter()
            .filter_map(|range| {
                let start_byte = python_expanded_comment_start(&source, range.start_byte);
                source.get(start_byte..range.end_byte).map(str::to_string)
            })
            .collect()
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

impl IAnalyzer for PythonAnalyzer {
    delegate_inner_procedure_fact_methods!();

    forward_relational_definition_batch!();

    #[cfg(any(test, feature = "test-support"))]
    fn test_hooks(&self) -> &dyn brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerTestHooks {
        self
    }

    forward_file_identity_invalidation!();

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
        fn import_statements(&self, file: &ProjectFile) -> Vec<String>;
    }

    delegate_inner_methods! {
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
        let scope = AnalyzerQueryScope::new(self);
        diagnostics::collect_python_semantic_diagnostics(self, scope.token(), file, source)
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

    fn import_analysis_provider(&self) -> Option<&dyn ImportAnalysisProvider> {
        Some(self)
    }

    fn type_hierarchy_provider(&self) -> Option<&dyn TypeHierarchyProvider> {
        Some(self)
    }

    fn python_class_hierarchy_provider_for(
        &self,
        _declaration: &CodeUnit,
    ) -> Option<&dyn brokk_bifrost_analysis::analyzer::usages::python_class_hierarchy::PythonClassHierarchyProvider>
{
        Some(self)
    }

    fn test_detection_provider(&self) -> Option<&dyn TestDetectionProvider> {
        Some(self)
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
            Language::Python,
            |source| detect_python_test_assertion_smells(file, source, &weights),
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
            Language::Python,
            |code_unit| build_clone_candidate_data(self, code_unit, weights),
        )
    }
}

#[cfg(any(test, feature = "test-support"))]
impl brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerTestHooks for PythonAnalyzer {
    delegate_inner_test_hook_methods! {
        fn reset_relational_definition_batch_call_count_for_test(&self);
    }

    delegate_inner_test_hook_methods! {
        fn relational_definition_batch_call_count_for_test(&self) -> usize;
    }

    delegate_inner_test_hook_methods! {
        fn reset_definition_candidates_query_count_for_test(&self);
    }

    delegate_inner_test_hook_methods! {
        fn definition_candidates_query_count_for_test(&self) -> usize;
    }

    delegate_inner_test_hook_methods! {
        fn reset_definition_prefetch_batch_count_for_test(&self);
    }

    delegate_inner_test_hook_methods! {
        fn definition_prefetch_batch_count_for_test(&self) -> usize;
    }

    delegate_inner_test_hook_methods! {
        fn reset_full_declaration_scan_count_for_test(&self);
    }

    delegate_inner_test_hook_methods! {
        fn full_declaration_scan_count_for_test(&self) -> usize;
    }

    fn reset_candidate_hydration_count_for_test(&self) {
        self.inner.reset_full_hydration_count_for_test();
    }

    delegate_inner_test_hook_methods! {
        fn full_candidate_hydration_count_for_test(&self) -> usize;
    }

    delegate_inner_test_hook_methods! {
        fn bulk_candidate_hydration_count_for_test(&self) -> usize;
    }

    delegate_inner_test_hook_methods! {
        fn reset_workspace_path_scan_count_for_test(&self);
    }

    fn workspace_path_scan_count_for_test(&self) -> usize {
        self.inner.test_hooks().workspace_path_scan_count_for_test()
    }
}

impl TestDetectionProvider for PythonAnalyzer {}

static PYTHON_USAGE_STRATEGY: PythonExportUsageGraphStrategy =
    PythonExportUsageGraphStrategy::new();

#[doc(hidden)]
pub struct PythonSupport;

fn unshadowed_builtin_print_parameter_count(site: &ExternalCalleeSite<'_>) -> Option<u32> {
    let start = site.callee_start_byte;
    let end = start.saturating_add("print".len());
    let reference = site
        .tree
        .root_node()
        .named_descendant_for_byte_range(start, end)?;
    let call = reference.parent()?;
    if reference.kind() != "identifier"
        || reference.utf8_text(site.source.as_bytes()).ok() != Some("print")
        || call.kind() != "call"
        || call
            .child_by_field_name("function")
            .is_none_or(|function| function.id() != reference.id())
        || type_flow::builtin_base_is_unshadowed(reference, site.source) != Some(true)
    {
        return None;
    }
    let arguments = call.child_by_field_name("arguments")?;
    let mut cursor = arguments.walk();
    u32::try_from(arguments.named_children(&mut cursor).count()).ok()
}

#[derive(Clone)]
enum CtypesModuleValue {
    Lookup(String),
    Library(String),
    Symbol { library: String, member: String },
}

fn ctypes_library_identity(value: &str) -> Option<String> {
    let file_name = std::path::Path::new(value)
        .file_name()
        .and_then(std::ffi::OsStr::to_str)?;
    let without_lib = file_name.strip_prefix("lib").unwrap_or(file_name);
    let name = [".dylib", ".dll", ".so"]
        .into_iter()
        .find_map(|suffix| without_lib.strip_suffix(suffix))
        .or_else(|| {
            let versioned_so = without_lib.find(".so.")?;
            let version = &without_lib[versioned_so + 4..];
            (!version.is_empty()
                && version
                    .chars()
                    .all(|character| character.is_ascii_digit() || character == '.'))
            .then_some(&without_lib[..versioned_so])
        })
        .unwrap_or(without_lib);
    (!name.is_empty()
        && name
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || character == '_'))
    .then(|| name.to_owned())
}

fn imported_python_module_path(
    expression: tree_sitter::Node<'_>,
    source: &str,
    imports: &HashMap<String, String>,
) -> Option<String> {
    let path = python_static_attribute_path(expression)?;
    let root = node_source_text(path.first().copied()?, source);
    let mut canonical = imports.get(root)?.clone();
    for segment in path.iter().skip(1) {
        canonical.push('.');
        canonical.push_str(node_source_text(*segment, source));
    }
    Some(canonical)
}

fn ctypes_value_from_expression(
    expression: tree_sitter::Node<'_>,
    source: &str,
    imports: &HashMap<String, String>,
    lookups: &HashMap<String, String>,
    libraries: &HashMap<String, String>,
    symbols: &HashMap<String, (String, String)>,
) -> Option<CtypesModuleValue> {
    if expression.kind() == "identifier" {
        let name = node_source_text(expression, source);
        return lookups
            .get(name)
            .cloned()
            .map(CtypesModuleValue::Lookup)
            .or_else(|| libraries.get(name).cloned().map(CtypesModuleValue::Library))
            .or_else(|| {
                symbols
                    .get(name)
                    .map(|(library, member)| CtypesModuleValue::Symbol {
                        library: library.clone(),
                        member: member.clone(),
                    })
            });
    }
    if expression.kind() == "attribute"
        && let Some(path) = python_static_attribute_path(expression)
        && path.len() == 2
        && let Some((receiver, member)) = path.first().zip(path.last())
        && let Some(library) = libraries.get(node_source_text(*receiver, source))
    {
        return Some(CtypesModuleValue::Symbol {
            library: library.clone(),
            member: node_source_text(*member, source).to_owned(),
        });
    }
    if expression.kind() != "call" {
        return None;
    }
    let function = expression.child_by_field_name("function")?;
    let canonical_function = imported_python_module_path(function, source, imports)?;
    let arguments = expression.child_by_field_name("arguments")?;
    let first_argument = {
        let mut cursor = arguments.walk();
        arguments.named_children(&mut cursor).next()?
    };
    if canonical_function == "ctypes.util.find_library" {
        return ctypes_library_identity(python_plain_string_literal(first_argument, source)?)
            .map(CtypesModuleValue::Lookup);
    }
    if canonical_function == "ctypes.CDLL" {
        let library = if first_argument.kind() == "call" {
            match ctypes_value_from_expression(
                first_argument,
                source,
                imports,
                lookups,
                libraries,
                symbols,
            )? {
                CtypesModuleValue::Lookup(library) => library,
                CtypesModuleValue::Library(_) | CtypesModuleValue::Symbol { .. } => return None,
            }
        } else if first_argument.kind() == "identifier" {
            lookups
                .get(node_source_text(first_argument, source))?
                .clone()
        } else {
            ctypes_library_identity(python_plain_string_literal(first_argument, source)?)?
        };
        return Some(CtypesModuleValue::Library(library));
    }
    None
}

fn python_call_parts<'tree>(
    site: &ExternalCalleeSite<'tree>,
) -> Option<(tree_sitter::Node<'tree>, tree_sitter::Node<'tree>)> {
    let start = site.callee_start_byte;
    let mut callee = site
        .tree
        .root_node()
        .named_descendant_for_byte_range(start, start.checked_add(1)?)?;
    loop {
        let parent = callee.parent()?;
        if parent.kind() == "attribute" && parent.child_by_field_name("attribute") == Some(callee) {
            callee = parent;
            continue;
        }
        if parent.kind() == "call" && parent.child_by_field_name("function") == Some(callee) {
            return Some((callee, parent));
        }
        return None;
    }
}

fn ctypes_loaded_symbol_identity(site: &ExternalCalleeSite<'_>) -> Option<ImportedExternalCallee> {
    let (callee, call) = python_call_parts(site)?;
    let root = site.tree.root_node();
    let path = python_static_attribute_path(callee)?;
    let source = site.source;
    let reference_name = node_source_text(path.first().copied()?, source);
    let mut imports = HashMap::default();
    let mut lookups = HashMap::default();
    let mut libraries = HashMap::default();
    let mut symbols = HashMap::default();
    let mut cursor = root.walk();
    for statement in root.named_children(&mut cursor) {
        if statement.start_byte() >= callee.start_byte() {
            break;
        }
        if matches!(
            statement.kind(),
            "import_statement" | "import_from_statement"
        ) {
            for import in python_import_infos_from_node(statement, source) {
                let Some(local) = import.identifier.as_deref() else {
                    continue;
                };
                let Some(details) = python_import_details(&import) else {
                    continue;
                };
                let canonical = match details {
                    PythonImportDetails::Import { module, alias } => {
                        if module != "ctypes" && !module.starts_with("ctypes.") {
                            None
                        } else if alias.is_some() {
                            Some(module)
                        } else {
                            Some("ctypes".to_owned())
                        }
                    }
                    PythonImportDetails::FromImport {
                        module,
                        name,
                        wildcard: false,
                        ..
                    } if module == "ctypes" || module == "ctypes.util" => {
                        Some(format!("{module}.{name}"))
                    }
                    PythonImportDetails::FromImport { .. } => None,
                };
                imports.remove(local);
                lookups.remove(local);
                libraries.remove(local);
                symbols.remove(local);
                if let Some(canonical) = canonical {
                    imports.insert(local.to_owned(), canonical);
                }
            }
            continue;
        }
        if statement.kind() != "expression_statement" {
            continue;
        }
        let Some(assignment) = statement.named_child(0) else {
            continue;
        };
        if assignment.kind() != "assignment" {
            continue;
        }
        let (targets, value) = python_assignment_chain(assignment);
        let Some(value) = value else {
            continue;
        };
        if targets.is_empty() || targets.iter().any(|target| target.kind() != "identifier") {
            continue;
        }
        let value =
            ctypes_value_from_expression(value, source, &imports, &lookups, &libraries, &symbols);
        for target in targets {
            let name = node_source_text(target, source);
            imports.remove(name);
            lookups.remove(name);
            libraries.remove(name);
            symbols.remove(name);
            match value.as_ref() {
                Some(CtypesModuleValue::Lookup(library)) => {
                    lookups.insert(name.to_owned(), library.clone());
                }
                Some(CtypesModuleValue::Library(library)) => {
                    libraries.insert(name.to_owned(), library.clone());
                }
                Some(CtypesModuleValue::Symbol { library, member }) => {
                    symbols.insert(name.to_owned(), (library.clone(), member.clone()));
                }
                None => {}
            }
        }
    }
    let (library, member) = if path.len() == 1 {
        symbols.get(reference_name).cloned()?
    } else if path.len() == 2 {
        let member = node_source_text(*path.last()?, source);
        (libraries.get(reference_name)?.clone(), member.to_owned())
    } else {
        return None;
    };
    if !matches!(
        brokk_bifrost_python::bindings::python_name_resolution_at(
            reference_name,
            path.first().copied()?,
            source,
        ),
        brokk_bifrost_python::bindings::PythonLexicalNameResolution::Unbound
    ) {
        return None;
    }
    let arguments = call.child_by_field_name("arguments")?;
    let mut cursor = arguments.walk();
    let parameter_count = u32::try_from(arguments.named_children(&mut cursor).count()).ok()?;
    let canonical_callee = format!("{library}.{member}");
    let proof =
        brokk_bifrost_analysis::analyzer::usages::get_definition::ExactExternalCallProof::python_imported_call(
            canonical_callee,
            parameter_count,
        );
    Some(ImportedExternalCallee::proven(
        proof,
        brokk_bifrost_analysis::analyzer::semantic::ResolverOwnedExternalCalleeIdentity::new(
            Language::Python,
            library.as_str(),
            member.as_str(),
        ),
    ))
}

fn python_imported_model_call_identity(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    site: &ExternalCalleeSite<'_>,
) -> Option<ImportedExternalCallee> {
    let python = resolve_analyzer::<PythonAnalyzer>(analyzer)?;
    let (callee, call) = python_call_parts(site)?;
    if let Some(identity) =
        python_external_receiver_method_identity(analyzer, python, file, site, callee, call)
    {
        return Some(identity);
    }
    let path = python_static_attribute_path(callee)?;
    let root_name = node_source_text(*path.first()?, site.source);
    let scope = AnalyzerQueryScope::new(python);
    let token = scope.token();
    if !python
        .import_binder_of(token, file)
        .bindings
        .contains_key(root_name)
    {
        return None;
    }
    let session = ResolutionSession::bounded(
        brokk_bifrost_core::analyzer::usages::receiver_analysis::INTERACTIVE_TYPE_LOOKUP_BUDGET,
        None,
    );
    let support = PythonDefinitionProvider::new(python, &session);
    let (module, member) = python_external_imported_symbol_bounded(
        &support,
        token,
        file,
        site.source,
        site.tree.root_node(),
        callee,
    )?;
    let canonical_callee = format!("{module}.{member}");
    let overlay = python.semantic_model_overlay()?;
    let matches = overlay.symbols_named(&canonical_callee);
    let [symbol] = matches.records.as_slice() else {
        return None;
    };
    let owner_matches = overlay.symbols_named(&module);
    let [owner] = owner_matches.records.as_slice() else {
        return None;
    };
    if matches.disposition
        != brokk_bifrost_analysis::analyzer::semantic_model::SemanticModelOverlayDisposition::Unique
        || symbol.language != Language::Python.config_label()
        || symbol.qualified_name != canonical_callee
        || symbol.kind != brokk_bifrost_analysis::analyzer::semantic_model::SemanticModelSymbolKind::Function
        || !symbol.callable_family_complete
        || symbol.provenance.ambiguous
        || symbol.provenance.completeness
            != brokk_bifrost_analysis::analyzer::semantic_model::SemanticModelCompleteness::Complete
        || owner_matches.disposition
            != brokk_bifrost_analysis::analyzer::semantic_model::SemanticModelOverlayDisposition::Unique
        || owner.language != Language::Python.config_label()
        || owner.kind != brokk_bifrost_analysis::analyzer::semantic_model::SemanticModelSymbolKind::Module
        || owner.qualified_name != module
        || symbol.owner_id.as_deref() != Some(owner.id.as_str())
    {
        return None;
    }
    let arguments = call.child_by_field_name("arguments")?;
    let mut cursor = arguments.walk();
    let parameter_count = u32::try_from(arguments.named_children(&mut cursor).count()).ok()?;
    let proof =
        brokk_bifrost_analysis::analyzer::usages::get_definition::ExactExternalCallProof::python_imported_call(
            canonical_callee,
            parameter_count,
        );
    Some(ImportedExternalCallee::proven(
        proof,
        brokk_bifrost_analysis::analyzer::semantic::ResolverOwnedExternalCalleeIdentity::new(
            Language::Python,
            module.as_str(),
            member.as_str(),
        ),
    ))
}

fn python_external_receiver_method_identity(
    analyzer: &dyn IAnalyzer,
    python: &PythonAnalyzer,
    file: &ProjectFile,
    site: &ExternalCalleeSite<'_>,
    callee: tree_sitter::Node<'_>,
    call: tree_sitter::Node<'_>,
) -> Option<ImportedExternalCallee> {
    if callee.kind() != "attribute" {
        return None;
    }
    let receiver = callee.child_by_field_name("object")?;
    let member = callee
        .child_by_field_name("attribute")?
        .utf8_text(site.source.as_bytes())
        .ok()?;
    let receiver_start = receiver.start_byte();
    let receiver_end = receiver.end_byte();
    let receiver_site = ResolvedReferenceSite {
        path: brokk_bifrost_core::path_utils::rel_path_string(file),
        text: receiver.utf8_text(site.source.as_bytes()).ok()?.to_owned(),
        range: Range {
            start_byte: receiver_start,
            end_byte: receiver_end,
            start_line: receiver.start_position().row + 1,
            end_line: receiver.end_position().row + 1,
        },
        focus_start_byte: receiver_start,
        focus_end_byte: receiver_end,
    };
    let scope = AnalyzerQueryScope::new(python);
    let receiver_type = match resolve_python_type_bounded(
        analyzer,
        scope.token(),
        file,
        site.source,
        Some(site.tree),
        &receiver_site,
        INTERACTIVE_TYPE_LOOKUP_BUDGET,
        None,
    ) {
        BoundedResolution::Complete { value, .. } => value,
        BoundedResolution::Exceeded { .. } | BoundedResolution::Cancelled { .. } => return None,
    };
    if receiver_type.status != TypeLookupStatus::Resolved || receiver_type.types.len() != 1 {
        return None;
    }
    let receiver_type = receiver_type.types.first()?;
    let model_id = receiver_type.semantic_model_id.as_deref()?;
    let overlay = analyzer.semantic_model_overlay()?;
    let owner_match = overlay.symbols_with_id(model_id);
    let [owner] = owner_match.records.as_slice() else {
        return None;
    };
    if owner_match.disposition
        != brokk_bifrost_analysis::analyzer::semantic_model::SemanticModelOverlayDisposition::Unique
        || owner.kind
            != brokk_bifrost_analysis::analyzer::semantic_model::SemanticModelSymbolKind::Class
        || owner.language != Language::Python.config_label()
        || owner.qualified_name != receiver_type.fqn
        || owner.provenance.ambiguous
        || owner.provenance.completeness
            != brokk_bifrost_analysis::analyzer::semantic_model::SemanticModelCompleteness::Complete
    {
        return None;
    }
    let declaration = python_external_member_declaration(&overlay, &owner.id, member)?;
    if declaration.kind
        != brokk_bifrost_analysis::analyzer::semantic_model::SemanticModelSymbolKind::Method
        || !declaration.has_receiver()
        || !declaration.has_complete_callable_shape_evidence()
        || declaration.structured_signature().is_none()
        || declaration.provenance.ambiguous
        || declaration.provenance.completeness
            != brokk_bifrost_analysis::analyzer::semantic_model::SemanticModelCompleteness::Complete
    {
        return None;
    }
    let declaration_owner_id = declaration.owner_id.as_deref()?;
    let declaration_owner_match = overlay.symbols_with_id(declaration_owner_id);
    let [declaration_owner] = declaration_owner_match.records.as_slice() else {
        return None;
    };
    if declaration_owner_match.disposition
        != brokk_bifrost_analysis::analyzer::semantic_model::SemanticModelOverlayDisposition::Unique
        || declaration_owner.kind
            != brokk_bifrost_analysis::analyzer::semantic_model::SemanticModelSymbolKind::Class
        || declaration_owner.language != Language::Python.config_label()
        || declaration_owner.provenance.ambiguous
        || declaration_owner.provenance.completeness
            != brokk_bifrost_analysis::analyzer::semantic_model::SemanticModelCompleteness::Complete
    {
        return None;
    }
    let arguments = call.child_by_field_name("arguments")?;
    let mut cursor = arguments.walk();
    let parameter_count = u32::try_from(arguments.named_children(&mut cursor).count()).ok()?;
    let proof =
        brokk_bifrost_analysis::analyzer::usages::get_definition::ExactExternalCallProof::python_bound_external_member(
            &declaration_owner.qualified_name,
            member,
            parameter_count,
        );
    Some(ImportedExternalCallee::proven(
        proof,
        brokk_bifrost_analysis::analyzer::semantic::ResolverOwnedExternalCalleeIdentity::new(
            Language::Python,
            declaration_owner.qualified_name.as_str(),
            member,
        ),
    ))
}

fn python_imports_ctypes(
    python: &PythonAnalyzer,
    token: QueryToken<'_>,
    file: &ProjectFile,
) -> bool {
    python
        .import_binder_of(token, file)
        .bindings
        .values()
        .any(|binding| matches!(binding.module_specifier.as_str(), "ctypes" | "ctypes.util"))
}

impl LanguageSupport for PythonSupport {
    /// Prove exact external receiver identities using this language's type flow.
    fn exact_external_receiver_identities(
        &self,
        workspace: &brokk_bifrost_analysis::analyzer::workspace::WorkspaceAnalyzer,
        procedure: &brokk_bifrost_analysis::analyzer::semantic::ProcedureHandle,
        call: &brokk_bifrost_analysis::analyzer::semantic::SemanticCallSite,
    ) -> Option<Vec<brokk_bifrost_analysis::analyzer::semantic::oracle::dispatch::ResolverOwnedExternalCalleeIdentity>>{
        python_exact_external_receiver_identities(workspace, procedure, call)
    }

    /// Select an effective external member under this language's inheritance rules.
    fn external_member_declaration<'a>(
        &self,
        overlay: &'a brokk_bifrost_analysis::analyzer::semantic_model::overlay::SemanticModelOverlay,
        owner_id: &str,
        member: &str,
    ) -> Option<&'a brokk_bifrost_analysis::analyzer::semantic_model::SemanticModelSymbol> {
        python_external_member_declaration(overlay, owner_id, member)
    }

    /// Prove the external class produced by a constructor call.
    fn external_class_call_identity(
        &self,
        workspace: &brokk_bifrost_analysis::analyzer::workspace::WorkspaceAnalyzer,
        procedure: &brokk_bifrost_analysis::analyzer::semantic::ProcedureHandle,
        call: &brokk_bifrost_analysis::analyzer::semantic::SemanticCallSite,
    ) -> Option<brokk_bifrost_semantic::analyzer::semantic::type_flow::ClassIdentity> {
        python_external_class_call_identity(workspace, procedure, call)
    }

    fn workspace_semantic_diagnostics(
        &self,
        workspace: &brokk_bifrost_analysis::analyzer::multi_analyzer::MultiAnalyzer,
        token: brokk_bifrost_core::analyzer::query_token::QueryToken<'_>,
        file: &ProjectFile,
        source: &str,
    ) -> Option<brokk_bifrost_core::analyzer::model::SemanticDiagnosticReport> {
        // Python's environment proof lives on the analyzer a host activated
        // packs against, which is this composite one and not the delegate. A
        // request routed straight to the delegate would see no overlay and no
        // discovery evidence, and would report every external import as an
        // unknown boundary.
        Some(diagnostics::collect_python_semantic_diagnostics(
            workspace, token, file, source,
        ))
    }

    fn knowledge(
        &self,
    ) -> &'static dyn brokk_bifrost_core::analyzer::language_knowledge::LanguageKnowledge {
        &brokk_bifrost_python::PythonKnowledge
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
                PythonAnalyzer::new_with_config_store_context(
                    project,
                    config,
                    store_context,
                    progress,
                )?,
            ),
        )
    }

    fn workspace_module_member_mutation_free(
        &self,
        analyzer: &dyn IAnalyzer,
        module: &str,
        member: &str,
        max_nodes: usize,
        keep_going: &dyn Fn() -> bool,
    ) -> Option<bool> {
        let python = resolve_analyzer::<PythonAnalyzer>(analyzer)?;
        let Ok(files) = python.project().all_files_shared() else {
            return Some(false);
        };
        for file in files.iter() {
            if !keep_going() {
                return None;
            }
            if brokk_bifrost_core::analyzer::common::language_for_file(file) != Language::Python {
                continue;
            }
            let Ok(source) = file.read_to_string() else {
                return Some(false);
            };
            let mut parser = tree_sitter::Parser::new();
            if parser
                .set_language(&tree_sitter_python::LANGUAGE.into())
                .is_err()
            {
                return Some(false);
            }
            let Some(tree) = parser.parse(&source, None) else {
                return Some(false);
            };
            if tree.root_node().has_error() {
                return Some(false);
            }
            let source_module =
                brokk_bifrost_python::declarations::python_module_name(python.project(), file);
            if brokk_bifrost_python::runtime_values::python_module_member_mutation(
                tree.root_node(),
                &source,
                &source_module,
                module,
                member,
                max_nodes,
            )
            .is_some()
            {
                return Some(false);
            }
        }
        keep_going().then_some(true)
    }

    fn external_field_read_discharges_gap(
        &self,
        workspace: &brokk_bifrost_analysis::analyzer::workspace::WorkspaceAnalyzer,
        procedure: &brokk_bifrost_analysis::analyzer::semantic::ProcedureHandle,
        gap: &brokk_bifrost_analysis::analyzer::semantic::SemanticGap,
    ) -> bool {
        type_flow::python_external_field_read_discharges_gap(workspace, procedure, gap)
    }

    fn expand_imported_external_callee(
        &self,
        analyzer: &dyn IAnalyzer,
        file: &ProjectFile,
        callee_text: &str,
        site: Option<&ExternalCalleeSite<'_>>,
    ) -> Option<ImportedExternalCallee> {
        let site = site?;
        if callee_text == "print"
            && let Some(parameter_count) = unshadowed_builtin_print_parameter_count(site)
        {
            return Some(ImportedExternalCallee::proven(
                brokk_bifrost_analysis::analyzer::usages::get_definition::ExactExternalCallProof::python_builtin_call(
                    "builtins.print",
                    parameter_count,
                ),
                brokk_bifrost_analysis::analyzer::semantic::ResolverOwnedExternalCalleeIdentity::new(
                    Language::Python,
                    "builtins",
                    "print",
                ),
            ));
        }
        let python = resolve_analyzer::<PythonAnalyzer>(analyzer)?;
        let scope = AnalyzerQueryScope::new(python);
        if python_imports_ctypes(python, scope.token(), file)
            && let Some(identity) = ctypes_loaded_symbol_identity(site)
        {
            return Some(identity);
        }
        python_imported_model_call_identity(analyzer, file, site)
    }

    fn procedure_syntax_roles(
        &self,
    ) -> Option<brokk_bifrost_analysis::analyzer::languages::ProcedureSyntaxRoles> {
        Some(semantic::PROCEDURE_SYNTAX_ROLES)
    }

    fn qualified_hierarchy_target(
        &self,
        declaring_locator_path: Option<&str>,
        declaring_qualified_name: &str,
        target: &str,
    ) -> Option<String> {
        if target.contains('.') {
            return None;
        }
        let module = declaring_locator_path
            .and_then(|path| external::python_module_name_from_relative(std::path::Path::new(path)))
            .or_else(|| {
                declaring_qualified_name
                    .rsplit_once('.')
                    .map(|(module, _)| module.to_owned())
            })?;
        Some(external::python_qualified_base_name(target, &module).into_owned())
    }

    fn signature_metadata_limited(
        &self,
        analyzer: &dyn IAnalyzer,
        unit: &CodeUnit,
        limit: usize,
    ) -> Option<LimitedQueryRows<SignatureMetadata>> {
        resolve_analyzer::<PythonAnalyzer>(analyzer)
            .map(|python| python.signature_metadata_limited(unit, limit))
    }

    fn signatures_limited(
        &self,
        analyzer: &dyn IAnalyzer,
        unit: &CodeUnit,
        limit: usize,
    ) -> Option<LimitedQueryRows<String>> {
        resolve_analyzer::<PythonAnalyzer>(analyzer)
            .map(|python| python.signatures_limited(unit, limit))
    }

    fn declaration_ranges_limited(
        &self,
        analyzer: &dyn IAnalyzer,
        unit: &CodeUnit,
        limit: usize,
    ) -> Option<LimitedQueryRows<Range>> {
        brokk_bifrost_analysis::analyzer::languages::with_resolved_analyzer::<PythonAnalyzer, _>(
            analyzer,
            |python| python.ranges_limited(unit, limit),
        )
    }

    fn forward_query_provider<'a>(
        &self,
        analyzer: &'a dyn IAnalyzer,
    ) -> Option<&'a dyn ForwardQueryProvider> {
        brokk_bifrost_analysis::analyzer::multi_analyzer::forward_query_provider::<PythonAnalyzer>(
            analyzer,
        )
    }

    fn refine_resolved_call_targets(
        &self,
        analyzer: &dyn IAnalyzer,
        token: QueryToken<'_>,
        file: &ProjectFile,
        site: &brokk_bifrost_analysis::analyzer::languages::ExternalCalleeSite<'_>,
        targets: &mut [brokk_bifrost_analysis::analyzer::usages::call_relations::CallDispatchTarget],
    ) {
        let Some(receiver_class) =
            crate::analyzer::usages::get_definition::python::python_bound_receiver_class_for_method_call(
                analyzer,
                token,
                file,
                site.source,
                site.tree,
                site.callee_start_byte,
            )
        else {
            return;
        };
        let Some(python) = resolve_analyzer::<PythonAnalyzer>(analyzer) else {
            return;
        };
        if type_flow::python_receiver_method_dispatch_may_be_bypassed(python, &receiver_class) {
            for target in targets {
                target.proof = brokk_bifrost_core::analyzer::usages::model::UsageProof::Unproven;
            }
        }
    }

    fn saved_default_argument_safety(
        &self,
        analyzer: &dyn IAnalyzer,
    ) -> Option<Arc<SavedDefaultArgumentSafety>> {
        resolve_analyzer::<PythonAnalyzer>(analyzer)
            .map(PythonAnalyzer::saved_default_argument_safety)
    }

    fn ecosystem(&self) -> UsageEcosystem {
        UsageEcosystem::Python
    }

    fn dependency_pack_resolver(
        &self,
    ) -> Option<&'static dyn brokk_bifrost_analysis::analyzer::semantic_model::dependency::DependencyResolver>{
        Some(&dependency_packs::PythonDependencyResolver)
    }

    fn publish_dependency_runtime(
        &self,
        workspace: &brokk_bifrost_analysis::analyzer::workspace::WorkspaceAnalyzer,
        config: &brokk_bifrost_core::analyzer::config::AnalyzerConfig,
        activation: &mut brokk_bifrost_analysis::analyzer::semantic_model::SemanticModelActivationRequest,
        context: &brokk_bifrost_analysis::analyzer::workspace::DependencyPackWorkspaceContext<'_>,
    ) -> Result<
        Option<brokk_bifrost_analysis::analyzer::store::python_runtime::PythonRuntimeProviderPublication>,
        brokk_bifrost_analysis::analyzer::store::StoreError,
    >{
        dependency_packs::python_runtime_publication(workspace, config, activation, context)
    }

    fn reference_usage_strategy(
        &self,
    ) -> &'static dyn brokk_bifrost_analysis::analyzer::usages::traits::GraphUsageAnalyzer {
        &PYTHON_USAGE_STRATEGY
    }

    fn reference_graph_backend(
        &self,
    ) -> brokk_bifrost_analysis::analyzer::languages::LanguageGraphBackend {
        brokk_bifrost_analysis::analyzer::languages::LanguageGraphBackend::Legacy(&PythonEdgePass)
    }

    fn definition_value_identity(
        &self,
        analyzer: &dyn brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer,
        request: &brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionLookupRequest,
        file: &brokk_bifrost_core::analyzer::model::ProjectFile,
        source: &str,
        cancellation: Option<&brokk_bifrost_core::cancellation::CancellationToken>,
    ) -> Option<brokk_bifrost_analysis::analyzer::usages::get_definition::ResolvedValueIdentity>
    {
        crate::analyzer::usages::get_definition::python::definition_value_identity(
            analyzer,
            request,
            file,
            source,
            cancellation,
        )
    }

    fn release_definition_file(
        &self,
        context: &mut brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionBatchContext<'_, '_>,
        file: &brokk_bifrost_core::analyzer::model::ProjectFile,
    ) {
        crate::analyzer::usages::get_definition::python::release_definition_file(context, file);
    }

    #[allow(clippy::too_many_arguments)]
    fn definition_tree(
        &self,
        analyzer: &dyn brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer,
        token: brokk_bifrost_core::analyzer::query_token::QueryToken<'_>,
        file: &brokk_bifrost_core::analyzer::model::ProjectFile,
        language: brokk_bifrost_core::analyzer::model::Language,
        source: &str,
        _primary_tree: Option<&tree_sitter::Tree>,
    ) -> Option<tree_sitter::Tree> {
        crate::analyzer::usages::get_definition::python::definition_tree(
            analyzer, token, file, language, source,
        )
    }

    fn definition_declared_import_route(
        &self,
        analyzer: &dyn brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer,
        token: brokk_bifrost_core::analyzer::query_token::QueryToken<'_>,
        file: &brokk_bifrost_core::analyzer::model::ProjectFile,
        leading: &str,
        evidence: &brokk_bifrost_analysis::analyzer::semantic_model::DependencyDiscoveryEvidence,
    ) -> bool {
        let Some(provider) = analyzer.import_analysis_provider_for_file(file) else {
            return false;
        };
        provider.import_info_of(token, file).iter().any(|import| {
            let binds = import.is_wildcard || import.local_name() == Some(leading);
            binds
                && import
                    .path
                    .as_ref()
                    .is_some_and(|path| evidence.declares_module_path(&path.render_segments(".")))
        })
    }

    fn definition_site_for_focus(
        &self,
        site: brokk_bifrost_core::analyzer::usages::reference_site::ResolvedReferenceSite,
        tree: &tree_sitter::Tree,
        source: &str,
        start: Option<usize>,
        end: Option<usize>,
    ) -> brokk_bifrost_core::analyzer::usages::reference_site::ResolvedReferenceSite {
        crate::analyzer::usages::get_definition::python::python_site_for_focus(
            site, tree, source, start, end,
        )
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
        crate::analyzer::usages::get_definition::python::resolve_definition_dispatch(
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
        crate::analyzer::usages::get_definition::python::python_call_reference_candidate(node)
    }

    fn dead_code(&self) -> DeadCodeSupport {
        DeadCodeSupport {
            strategy: None,
            bulk: Some(&PythonDeadCodeBulk),
        }
    }

    fn structural_receiver(&self) -> Option<&'static dyn StructuralReceiverResolver> {
        Some(&PythonSupport)
    }

    fn type_flow_adapter(
        &self,
    ) -> Option<&'static dyn brokk_bifrost_analysis::analyzer::semantic::type_flow::TypeFlowAdapter>
    {
        Some(&type_flow::PythonTypeFlowAdapter)
    }

    /// Protected: these are the importer files of the target's inferred export names,
    /// which the generic import-graph walk misses whenever the import goes through a
    /// package `__init__` re-export rather than the defining module.
    fn candidate_augmentation(&self, ctx: &CandidateCtx<'_>) -> Option<CandidateAugmentation> {
        Some(CandidateAugmentation::protected(
            python_usage_candidate_files(ctx.analyzer, ctx.target),
        ))
    }
}

struct PythonEdgePass;

impl LanguageEdgePass for PythonEdgePass {
    fn id(&self) -> EdgePassId {
        EdgePassId::Python
    }

    fn edge_sites(&self, ctx: &EdgeSiteScanCtx<'_>) -> Option<LanguageEdgeSites> {
        crate::analyzer::usages::python_graph::build_rooted_python_usage_edges(
            ctx.analyzer,
            ctx.fqns,
            ctx.keep_file,
        )
        .map(LanguageEdgeSites::Fqn)
    }

    fn edge_weights(&self, ctx: &EdgeWeightScanCtx<'_>) -> Option<LanguageEdgeWeights> {
        build_python_usage_edge_weights(ctx.analyzer, ctx.fqns, ctx.keep_file)
            .map(LanguageEdgeWeights::Fqn)
    }
}

impl StructuralReceiverResolver for PythonSupport {
    fn resolve_type_bounded(
        &self,
        query: BoundedReceiverQuery<'_>,
    ) -> BoundedResolution<TypeLookupOutcome> {
        let scope = AnalyzerQueryScope::new(query.analyzer);
        let token = scope.token();
        resolve_python_type_bounded(
            query.analyzer,
            token,
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
        brokk_bifrost_analysis::analyzer::languages::with_bounded_receiver_query(
            query,
            |query, token| {
                resolve_python_bounded(
                    query.analyzer,
                    token,
                    query.file,
                    query.source,
                    query.tree,
                    query.site,
                    query.budget,
                    query.cancellation,
                )
            },
        )
    }
}

struct PythonDeadCodeBulk;

impl DeadCodeBulkProof for PythonDeadCodeBulk {
    fn id(&self) -> EdgePassId {
        EdgePassId::Python
    }

    fn needs_precise_scan(&self, _routing: DeadCodeRouting<'_>) -> bool {
        false
    }

    fn preflight(&self, analyzer: &dyn IAnalyzer) -> DeadCodeBulkPreflight {
        ready_preflight(analyzer, Language::Python, "Python")
    }

    /// The only proof that resolves a bounded *target* set. Dead-code analysis needs
    /// every declaration as a possible caller but inbound edges for its candidates only,
    /// and Python's cached builder is the one that can express that split -- which is why
    /// the general edge passes, whose builders resolve every node, cannot serve here.
    fn build(
        &self,
        analyzer: &dyn IAnalyzer,
        candidates: &[CodeUnit],
    ) -> Option<DeadCodeBulkEdges> {
        let nodes = fqn_bulk_nodes(
            analyzer,
            Language::Python,
            |unit| unit.is_function() || unit.is_class(),
            candidates,
        );
        let targets = candidate_fqns(candidates);
        build_cached_python_usage_edges_for_targets(analyzer, &nodes, &targets)
            .map(DeadCodeBulkEdges::Fqn)
    }
}

impl brokk_bifrost_analysis::analyzer::multi_analyzer::LanguageAnalyzer for PythonAnalyzer {
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
        Box::new(PythonAnalyzer::clone_with_project(self, project))
    }

    fn clone_for_index_warm(
        &self,
        project: Arc<dyn Project>,
    ) -> Box<dyn brokk_bifrost_analysis::analyzer::multi_analyzer::LanguageAnalyzer> {
        Box::new(PythonAnalyzer::clone_with_project(self, project))
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
        Box::new(PythonAnalyzer::update_all_with_progress(self, progress))
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

    use brokk_bifrost_analysis::analyzer::semantic_model::DependencyDiscoveryOutcome;

    use brokk_bifrost_analysis::analyzer::semantic_model::DependencyPackAdapter;

    use brokk_bifrost_analysis::analyzer::semantic_model::DependencyPackLimits;

    use brokk_bifrost_analysis::analyzer::semantic_model::dependency::DependencyResolver;

    use brokk_bifrost_analysis::analyzer::semantic_model::DependencyResolverBounds;
    use brokk_bifrost_analysis::analyzer::semantic_model::{
        SemanticModelActivationEvidence, SemanticModelActivationRequest,
    };

    use brokk_bifrost_analysis::analyzer::store::StoreError;

    use brokk_bifrost_analysis::analyzer::workspace::DependencyPackWorkspaceContext;

    use brokk_bifrost_analysis::analyzer::workspace::READS_FILES_ONLY;

    use brokk_bifrost_core::analyzer::config::AnalyzerConfig;

    use brokk_bifrost_core::analyzer::project::Project;

    use crate::analyzer::PythonDependencyPackAdapter;

    use brokk_bifrost_analysis::analyzer::workspace::WorkspaceAnalyzer;

    use crate::analyzer::resolve_python_semantic_pack_dependencies;
    pub(crate) struct PythonDependencyResolver;

    impl DependencyResolver for PythonDependencyResolver {
        fn adapter(&self) -> &'static dyn DependencyPackAdapter {
            &PythonDependencyPackAdapter
        }

        fn dependency_inputs(&self) -> &'static [&'static str] {
            // Python discovery reads distribution metadata under the roots the
            // host configures, plus the workspace's own toolchain declaration
            // files, which key the standard-library pack selection (#1869).
            &[
                "METADATA",
                "RECORD",
                "top_level.txt",
                "pyproject.toml",
                ".python-version",
            ]
        }

        fn bounds(&self, config: &AnalyzerConfig) -> DependencyResolverBounds {
            DependencyResolverBounds {
                max_files_walked: config
                    .python
                    .environment
                    .as_ref()
                    .map(|environment| environment.limits.max_files_per_distribution),
                ..READS_FILES_ONLY
            }
        }

        fn adjust_limits(&self, config: &AnalyzerConfig, limits: &mut DependencyPackLimits) {
            if let Some(environment) = &config.python.environment {
                limits.max_artifacts_per_dependency = limits
                    .max_artifacts_per_dependency
                    .max(environment.limits.max_files_per_distribution);
            }
        }

        fn resolve(
            &self,
            config: &AnalyzerConfig,
            project: &dyn Project,
            limits: &DependencyPackLimits,
            cancellation: Option<&brokk_bifrost_core::cancellation::CancellationToken>,
        ) -> DependencyDiscoveryOutcome {
            resolve_python_semantic_pack_dependencies(&config.python, project, limits, cancellation)
        }
    }

    pub(crate) fn python_runtime_publication(
        workspace: &WorkspaceAnalyzer,
        config: &AnalyzerConfig,
        activation: &mut SemanticModelActivationRequest,
        context: &DependencyPackWorkspaceContext<'_>,
    ) -> Result<
        Option<brokk_bifrost_analysis::analyzer::store::python_runtime::PythonRuntimeProviderPublication>,
        StoreError,
    >{
        use crate::analyzer::python::runtime_artifact as verified;

        use brokk_bifrost_analysis::analyzer::store::python_runtime as stored;
        if config.python.runtime_environments.is_empty() {
            return Ok(None);
        }
        let python = brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer::<
            crate::analyzer::PythonAnalyzer,
        >(workspace.analyzer())
        .ok_or_else(|| StoreError::new("Python runtime configuration has no Python analyzer"))?;
        let (store, snapshot) = python.python_runtime_store_snapshot().ok_or_else(|| {
            StoreError::stale_generation("Python runtime configuration has no selected snapshot")
        })?;
        let report = verified::verify_python_runtime_artifacts(
            workspace.analyzer().project().root(),
            &config.python.runtime_environments,
            &context.limits,
            Some(context.cancellation),
        );
        if report.cancelled {
            return Err(StoreError::new("Python runtime verification cancelled"));
        }
        let configuration = serde_json::to_vec(&config.python.runtime_environments)
            .map_err(|error| StoreError::new(error.to_string()))?;
        let mut environments = Vec::new();
        for (index, environment) in config.python.runtime_environments.iter().enumerate() {
            let mut artifacts = Vec::new();
            for artifact in report
                .artifacts
                .iter()
                .filter(|artifact| artifact.environment_index == index)
            {
                let mut providers = Vec::new();
                let members = artifact
                    .modules
                    .iter()
                    .enumerate()
                    .map(|(member_index, module)| {
                        if let Some(name) = &module.import_name {
                            providers.push(stored::PythonRuntimeProviderInput {
                                import_name: name.clone(),
                                member_index: Some(member_index),
                                status: match module.import_status {
                                    verified::PythonRuntimeImportStatus::Unresolved => {
                                        stored::PythonRuntimeBindingStatus::Unresolved
                                    }
                                    verified::PythonRuntimeImportStatus::Conflict => {
                                        stored::PythonRuntimeBindingStatus::Conflict
                                    }
                                },
                            });
                        }
                        stored::PythonRuntimeMemberInput {
                            archive_member_path: module.archive_member_path.clone(),
                            installed_path: module.installed_path.clone(),
                            member_sha256: module.member_sha256.clone(),
                            installed_sha256: module.installed_sha256.clone(),
                            installed_bytes_match: module.installed_bytes_match,
                            role: match (module.runtime, module.stub) {
                                (true, false) => stored::PythonRuntimeMemberRole::Runtime,
                                (false, true) => stored::PythonRuntimeMemberRole::Stub,
                                (true, true) => stored::PythonRuntimeMemberRole::RuntimeAndStub,
                                (false, false) => stored::PythonRuntimeMemberRole::Other,
                            },
                            status: match module.status {
                                verified::PythonRuntimeModuleStatus::BytesMatched => {
                                    stored::PythonRuntimeStatus::BytesMatched
                                }
                                verified::PythonRuntimeModuleStatus::StubOnly => {
                                    stored::PythonRuntimeStatus::StubOnly
                                }
                                verified::PythonRuntimeModuleStatus::MissingInstalled => {
                                    stored::PythonRuntimeStatus::MissingInstalled
                                }
                                verified::PythonRuntimeModuleStatus::ContentMismatch => {
                                    stored::PythonRuntimeStatus::ContentMismatch
                                }
                                verified::PythonRuntimeModuleStatus::Unsupported => {
                                    stored::PythonRuntimeStatus::Unsupported
                                }
                                verified::PythonRuntimeModuleStatus::Unresolved => {
                                    stored::PythonRuntimeStatus::Unresolved
                                }
                            },
                            diagnostic: None,
                        }
                    })
                    .collect();
                if let Some(identity) = &artifact.identity {
                    activation.evidence.push(SemanticModelActivationEvidence {
                        language: "python".into(),
                        ecosystem: "python".into(),
                        package: Some(
                            brokk_bifrost_analysis::analyzer::semantic_model::CatalogCoordinate {
                                name: identity.purl().to_owned(),
                                version: None,
                            },
                        ),
                        module: None,
                        toolchain: None,
                        target: None,
                        configuration: None,
                        artifact_sha256: Some(identity.archive_sha256().to_owned()),
                    });
                }
                artifacts.push(stored::PythonRuntimeArtifactInput {
                    purl: artifact.coordinate.clone(),
                    raw_version: artifact.raw_version.clone(),
                    archive_sha256: artifact.archive_sha256.clone(),
                    archive_path: artifact.archive_path.clone(),
                    installed_root: artifact.installed_root.clone(),
                    status: match artifact.status {
                        verified::PythonRuntimeArtifactStatus::ArchiveVerified => {
                            stored::PythonRuntimeStatus::ArchiveVerified
                        }
                        verified::PythonRuntimeArtifactStatus::Incomplete => {
                            stored::PythonRuntimeStatus::Incomplete
                        }
                        verified::PythonRuntimeArtifactStatus::Unresolved => {
                            stored::PythonRuntimeStatus::Unresolved
                        }
                        verified::PythonRuntimeArtifactStatus::Conflicting => {
                            stored::PythonRuntimeStatus::Conflicting
                        }
                        verified::PythonRuntimeArtifactStatus::Cancelled => {
                            stored::PythonRuntimeStatus::Cancelled
                        }
                    },
                    diagnostic: None,
                    members,
                    providers,
                });
            }
            let frontiers = report
                .frontiers
                .iter()
                .filter(|frontier| frontier.environment_index == index)
                .map(|frontier| stored::PythonRuntimeFrontierInput {
                    kind: match frontier.kind {
                        verified::PythonRuntimeFrontierKind::ExtraInstalledCandidate => {
                            stored::PythonRuntimeFrontierKind::ExtraInstalledCandidate
                        }
                        verified::PythonRuntimeFrontierKind::SourceShadowCandidate => {
                            stored::PythonRuntimeFrontierKind::SourceShadowCandidate
                        }
                        verified::PythonRuntimeFrontierKind::CompetingRuntimeProvider => {
                            stored::PythonRuntimeFrontierKind::CompetingRuntimeProvider
                        }
                        verified::PythonRuntimeFrontierKind::NamespaceContributor => {
                            stored::PythonRuntimeFrontierKind::NamespaceContributor
                        }
                        verified::PythonRuntimeFrontierKind::PackageInitializerEffects => {
                            stored::PythonRuntimeFrontierKind::PackageInitializerEffects
                        }
                        verified::PythonRuntimeFrontierKind::CandidatePathCollision => {
                            stored::PythonRuntimeFrontierKind::CandidatePathCollision
                        }
                        verified::PythonRuntimeFrontierKind::CandidateIdentityUnknown => {
                            stored::PythonRuntimeFrontierKind::CandidateIdentityUnknown
                        }
                        verified::PythonRuntimeFrontierKind::MissingInstalledCandidate => {
                            stored::PythonRuntimeFrontierKind::MissingInstalledCandidate
                        }
                        verified::PythonRuntimeFrontierKind::SymlinkSkipped => {
                            stored::PythonRuntimeFrontierKind::SymlinkSkipped
                        }
                        verified::PythonRuntimeFrontierKind::PathUnreadable => {
                            stored::PythonRuntimeFrontierKind::PathUnreadable
                        }
                        verified::PythonRuntimeFrontierKind::ScanLimit => {
                            stored::PythonRuntimeFrontierKind::ScanLimit
                        }
                        verified::PythonRuntimeFrontierKind::ScanDepthLimit => {
                            stored::PythonRuntimeFrontierKind::ScanDepthLimit
                        }
                        verified::PythonRuntimeFrontierKind::ImportPathOrderUnknown => {
                            stored::PythonRuntimeFrontierKind::ImportPathOrderUnknown
                        }
                        verified::PythonRuntimeFrontierKind::ImportHookSemanticsUnknown => {
                            stored::PythonRuntimeFrontierKind::ImportHookSemanticsUnknown
                        }
                    },
                    root: frontier.root.clone(),
                    path: frontier.path.clone(),
                    import_name: frontier.import_name.clone(),
                    message: frontier.message.clone(),
                })
                .collect();
            let declared = report
                .declared_environments
                .get(index)
                .and_then(Option::as_ref);
            environments.push(stored::PythonRuntimeEnvironmentInput {
                declared_environment: declared.and(environment.declared_environment.clone()),
                project_config: declared.map(|proof| proof.project_config().clone()),
                source_scope: environment.source_root.clone(),
                status: if report.scope_complete {
                    stored::PythonRuntimeStatus::ArchiveVerified
                } else {
                    stored::PythonRuntimeStatus::Incomplete
                },
                diagnostic: None,
                artifacts,
                frontiers,
            });
        }
        // Diagnostic formatting is SQL-independent, deterministic input evidence;
        // this aggregate never substitutes for a raw wheel artifact digest.
        let mut digest_input = configuration.clone();
        digest_input.extend(format!("{environments:?}").as_bytes());
        let evidence_digest =
            brokk_bifrost_core::analyzer::canonical_hash::sha256_bytes(&digest_input);
        let publication = store.publish_python_runtime_providers(
            &snapshot,
            Some(brokk_bifrost_analysis::analyzer::store::workspace_inputs::WorkspaceConfigurationInput::new(
                ".bifrost/python-runtime-selection.json".into(),
                configuration.into_boxed_slice(),
            )),
            evidence_digest,
            environments,
            context.cancellation,
        )?;
        python.install_python_runtime_snapshot(&snapshot, publication.snapshot.clone())?;
        Ok(Some(publication))
    }
}

use brokk_bifrost_analysis::{
    delegate_inner_methods, delegate_inner_procedure_fact_methods,
    forward_file_identity_invalidation, forward_relational_definition_batch,
    impl_forward_query_provider,
};

#[cfg(any(test, feature = "test-support"))]
use brokk_bifrost_analysis::delegate_inner_test_hook_methods;

impl brokk_bifrost_analysis::analyzer::store::StoreLanguageSupport for PythonSupport {
    fn include_native_metadata_paths(
        &self,
        project: &dyn brokk_bifrost_analysis::analyzer::Project,
        files: &std::collections::BTreeSet<ProjectFile>,
        inputs: &mut std::collections::BTreeSet<ProjectFile>,
    ) -> std::io::Result<()> {
        use brokk_bifrost_analysis::analyzer::store::workspace_inputs::metadata_ancestor_directories;
        for directory in metadata_ancestor_directories(files.iter().filter(|file| {
            file.rel_path()
                .extension()
                .is_some_and(|extension| extension == "py")
        })) {
            for name in ["pyproject.toml", "setup.py", "__init__.py"] {
                let path = std::path::Path::new(name);
                if self.is_configuration_input_path(path)
                    && let Some(file) = project.file_by_rel_path(&directory.join(path))
                {
                    inputs.insert(file);
                }
            }
        }
        Ok(())
    }

    fn qualified_member_registrations(
        &self,
    ) -> &'static [brokk_bifrost_analysis::analyzer::resolution::fact_source::QualifiedMemberRegistration]{
        use brokk_bifrost_analysis::analyzer::resolution::fact_source::QualifiedMemberRegistration;
        static REGISTRATION: [QualifiedMemberRegistration; 1] = [QualifiedMemberRegistration {
            language: Language::Python,
            hierarchy_identity: 0x5059_0001,
            member_access: true,
        }];
        &REGISTRATION
    }

    fn publish_native_source_rows(
        &self,
        tx: &rusqlite::Transaction<'_>,
        blob: i64,
        facts: &brokk_bifrost_core::analyzer::resolution_facts::FileResolutionFacts,
        cancellation: &brokk_bifrost_analysis::CancellationToken,
    ) -> brokk_bifrost_analysis::analyzer::store::Result<()> {
        use brokk_bifrost_analysis::analyzer::store::{python_binding_rows, python_member_rows};
        python_binding_rows::publish(tx, blob, facts, cancellation)?;
        python_member_rows::publish(tx, blob, facts, cancellation)
    }

    fn has_conditional_type_seeds(&self) -> bool {
        true
    }

    fn selected_conditional_type_seed(
        &self,
        selection: &brokk_bifrost_analysis::analyzer::store::resolution_selection::SelectedResolutionMountInventory<'_>,
        slot: brokk_bifrost_analysis::analyzer::resolution::SemanticId,
        cancellation: &brokk_bifrost_analysis::CancellationToken,
    ) -> brokk_bifrost_analysis::analyzer::store::Result<
        Option<brokk_bifrost_analysis::analyzer::resolution::ConditionalTypeSeed>,
    > {
        brokk_bifrost_analysis::analyzer::store::python_member_rows::receiver_seed(
            selection,
            slot,
            cancellation,
        )
    }

    fn selected_implicit_base_inputs(
        &self,
        selection: &brokk_bifrost_analysis::analyzer::store::resolution_selection::SelectedResolutionMountInventory<'_>,
        environment: i64,
        declared_version: Option<(u16, u16)>,
        owner: brokk_bifrost_analysis::analyzer::resolution::SemanticId,
        cancellation: &brokk_bifrost_analysis::CancellationToken,
    ) -> brokk_bifrost_analysis::analyzer::store::Result<
        Option<brokk_bifrost_analysis::analyzer::resolution::ImplicitBaseInputs>,
    > {
        use brokk_bifrost_analysis::analyzer::resolution::{
            ClassCreationKind, ImplicitBaseAuthority, ImplicitBaseInputs, ImplicitRootObject,
            ResolutionCompletion, SemanticId, SharedNameInterner, universe,
        };
        use brokk_bifrost_core::analyzer::resolution_facts::ResolutionNamespace;
        use brokk_bifrost_python::intrinsics::{PythonVersion, implicit_base};
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        let version = declared_version.map(|(major, minor)| PythonVersion::new(major, minor));
        let root = implicit_base(version).map(|builtin| {
            let entry = universe::lookup(
                Language::Python,
                ResolutionNamespace::TypeOrValue,
                builtin.name,
            )
            .expect("implicit root belongs to the Python universe");
            SemanticId::shared_name(
                selection
                    .shared_names()
                    .intern(universe::identity_digest(entry)),
            )
        });
        if root == Some(owner) {
            return Ok(Some(ImplicitBaseInputs {
                written_inventory_complete: true,
                written_base_count: 0,
                creation: ClassCreationKind::Ordinary,
                root_object: None,
                authority: ImplicitBaseAuthority::Intrinsic { descriptor: owner },
                completion: ResolutionCompletion::Complete,
            }));
        }
        let Some(mut inputs) =
            brokk_bifrost_analysis::analyzer::store::python_member_rows::implicit_inputs(
                selection,
                environment,
                owner,
                cancellation,
            )?
        else {
            return Ok(None);
        };
        if inputs.creation == ClassCreationKind::Ordinary
            && inputs.written_inventory_complete
            && inputs.written_base_count == 0
            && let Some(root) = root
        {
            // Python's no-written-base rule uses the intrinsic object, even
            // when lexical lookup of the spelling object would be shadowed.
            inputs.root_object = Some(ImplicitRootObject {
                identity: root,
                authority: ImplicitBaseAuthority::Intrinsic { descriptor: root },
                occurrence: owner,
            });
            inputs.completion = ResolutionCompletion::Complete;
        }
        Ok(Some(inputs))
    }

    fn is_configuration_input_path(&self, path: &std::path::Path) -> bool {
        matches!(
            path.file_name().and_then(|name| name.to_str()),
            Some("pyproject.toml" | "setup.py" | "__init__.py")
        )
    }
}
