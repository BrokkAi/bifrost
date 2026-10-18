//! The analyzer-owned shim over [`brokk_bifrost_python`].
//!
//! What lives here is everything the language crate cannot name: the
//! [`PythonAnalyzer`] newtype and its seven moka caches and four
//! `PoolSafeMemo`s; the accessors that implement
//! [`brokk_bifrost_python::graph_support::PythonSource`] and
//! [`brokk_bifrost_python::graph_support::PythonUsageSource`] out of them; the
//! `PythonAdapter` forwarding shell; the `IAnalyzer`/`CodeUnitIndex` impls; and
//! the `LanguageSupport` SPI block.

mod adapter;
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
pub mod packaging;
pub mod runtime_artifact;
pub(crate) mod runtime_binding;
pub(crate) mod runtime_environment;
pub(crate) mod runtime_provider;
mod semantic;
pub(crate) mod source_publication;
pub(crate) mod source_storage;
mod structural;
mod type_flow;
use crate::analyzer::QueryToken;
use crate::analyzer::Range;
pub(crate) use type_flow::{
    python_attribute_value_terminal_range, python_exact_external_receiver_identities,
    python_external_class_call_identity, python_external_member_declaration,
    python_external_value_member_on_workspace_class,
};

pub(crate) use brokk_bifrost_python::syntax::{
    python_deferred_annotation_identifier_ranges, python_node_is_in_annotation,
};

use crate::analyzer::cache_weight::weight_code_unit_vec;
use crate::analyzer::clone_detection::detect_language_structural_clone_smells;
use crate::analyzer::languages::{
    BoundedReceiverQuery, CandidateAugmentation, CandidateCtx, DeadCodeBulkEdges,
    DeadCodeBulkPreflight, DeadCodeBulkProof, DeadCodeRouting, DeadCodeSupport, EdgePassId,
    EdgeSiteScanCtx, EdgeWeightScanCtx, ExternalCalleeSite, ImportedExternalCallee,
    LanguageEdgePass, LanguageEdgeSites, LanguageEdgeWeights, LanguageSupport,
    SavedDefaultArgumentSafety, StructuralReceiverResolver, candidate_fqns, fqn_bulk_nodes,
    ready_preflight,
};
use crate::analyzer::store::LimitedQueryRows;
use crate::analyzer::usages::get_definition::{
    BoundedResolution, DefinitionLookupOutcome, PythonDefinitionProvider, ResolutionSession,
    python_external_imported_symbol_bounded, resolve_python_bounded,
};
use crate::analyzer::usages::get_type::{
    TypeLookupOutcome, TypeLookupStatus, resolve_python_type_bounded,
};
use crate::analyzer::usages::python_graph::{
    PythonExportUsageGraphStrategy, build_cached_python_usage_edges_for_targets,
    build_python_usage_edge_weights, python_usage_candidate_files,
};
use crate::analyzer::usages::receiver_analysis::INTERACTIVE_TYPE_LOOKUP_BUDGET;
use crate::analyzer::usages::reference_site::ResolvedReferenceSite;
use crate::analyzer::usages::workspace_graph::UsageEcosystem;
use crate::analyzer::usages::{ExportIndex, ImportBinder};
use crate::analyzer::weighted_cache::{
    build_weighted_cache, weight_code_unit_set, weight_export_index, weight_project_file_set,
};
use crate::analyzer::{
    AnalyzerConfig, AnalyzerStoreContext, BuildProgress, BulkFileStateSource, CloneSmell,
    CloneSmellWeights, CodeUnit, DescendantIndexVariant, DirectDescendantIndex,
    ForwardQueryProvider, IAnalyzer, ImportAnalysisProvider, KeyedPoolSafeMemo, Language,
    PoolSafeMemo, Project, ProjectFile, SignatureMetadata, TestAssertionSmell,
    TestAssertionWeights, TestDetectionProvider, TreeSitterAnalyzer, TypeHierarchyProvider,
    build_reverse_import_index, resolve_analyzer,
};
use crate::hash::{HashMap, HashSet};
use crate::profiling;
use brokk_bifrost_core::analyzer::common::node_source_text;
use brokk_bifrost_core::analyzer::prepared_syntax::IndexedFileFacts;
use brokk_bifrost_python::imports::{
    PythonImportDetails, python_assignment_chain, python_import_details,
    python_import_infos_from_node,
};
use brokk_bifrost_python::syntax::{python_plain_string_literal, python_static_attribute_path};
use moka::sync::Cache;
use std::collections::BTreeSet;
use std::sync::Arc;

use crate::analyzer::{AnalyzerQueryScope, QueryScope};
pub(crate) use adapter::PythonAdapter;
use brokk_bifrost_python::declarations::python_expanded_comment_start;
use brokk_bifrost_python::graph_support::{
    PythonModuleSpellings, PythonSource, PythonUsageSource, compute_export_index_of,
    import_binder_from_imports, render_skeleton_recursive,
};
pub(crate) use brokk_bifrost_python::graph_support::{
    resolve_module_code_unit, retain_modules_for_importer,
};
pub(crate) use brokk_bifrost_python::imports::resolve_fqn_candidates;
use brokk_bifrost_python::imports::resolve_imports_batched;
use brokk_bifrost_python::source_facts::PythonSourceFactProvider;
use brokk_bifrost_python::test_detection::detect_python_test_assertion_smells;
use brokk_bifrost_python::usage_index::PythonUsageIndex;
pub(crate) use brokk_bifrost_python::usage_index::{
    ModuleBindingEventKind, ModuleBindingTimeline, usage_resolve_module_files,
};
use cache::{
    PythonClassMutationKey, PythonModuleMemberMutationKey, PythonUsageEdgesKey,
    build_python_class_mutation_cache, build_python_module_member_mutation_cache,
    weight_import_binder, weight_module_global_source_facts, weight_python_usage_edges,
};
use clones::build_clone_candidate_data;
pub use exception_identity::{python_builtin_exception_is_subclass, python_builtin_exception_name};

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
        (crate::analyzer::store::GenerationId, git2::Oid, ProjectFile),
        Arc<brokk_bifrost_python::source_facts::PythonFileSourceFacts>,
    >,
    module_global_source_facts: Cache<
        (crate::analyzer::store::GenerationId, git2::Oid, ProjectFile),
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
    usage_edges:
        Cache<PythonUsageEdgesKey, Arc<crate::analyzer::usages::inverted_edges::UsageEdges>>,
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

crate::analyzer::impl_forward_query_provider!(PythonAnalyzer);

impl PythonAnalyzer {
    pub(crate) fn update_all_with_progress(
        &self,
        progress: Option<crate::analyzer::BuildProgress>,
    ) -> Self {
        Self::from_inner(
            self.inner.update_all_with_progress(progress),
            self.memo_budget,
        )
    }

    pub(crate) fn install_python_runtime_snapshot(
        &self,
        base: &crate::analyzer::store::WorkspaceSnapshotId,
        published: crate::analyzer::store::WorkspaceSnapshotId,
    ) -> Result<(), crate::analyzer::store::StoreError> {
        self.inner.install_python_runtime_snapshot(base, published)
    }

    pub(crate) fn python_runtime_store_snapshot(
        &self,
    ) -> Option<(
        Arc<crate::analyzer::store::AnalyzerStore>,
        crate::analyzer::store::WorkspaceSnapshotId,
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
    ) -> LimitedQueryRows<crate::analyzer::Range> {
        self.inner.ranges_limited(code_unit, limit)
    }

    crate::analyzer::tree_sitter_analyzer::delegate_inner_methods! {
        pub(crate) fn signature_metadata_limited(
        &self,
        code_unit: &CodeUnit,
        limit: usize,
    ) -> LimitedQueryRows<SignatureMetadata>;
    }

    crate::analyzer::tree_sitter_analyzer::delegate_inner_methods! {
        pub(crate) fn signatures_limited(
        &self,
        code_unit: &CodeUnit,
        limit: usize,
    ) -> LimitedQueryRows<String>;
    }

    crate::analyzer::tree_sitter_analyzer::delegate_inner_methods! {
        #[doc(hidden)]
        pub fn reset_full_hydration_count_for_test(&self);
    }

    crate::analyzer::tree_sitter_analyzer::delegate_inner_methods! {
        #[doc(hidden)]
        pub fn full_hydration_count_for_test(&self) -> usize;
    }

    #[cfg(test)]
    pub(crate) fn prepared_syntax_parse_count_for_test(&self, file: &ProjectFile) -> usize {
        self.inner.prepared_syntax_parse_count_for_test(file)
    }

    pub(crate) fn clone_with_project(&self, project: Arc<dyn Project>) -> Self {
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
    ) -> Result<Self, crate::analyzer::store::StoreError> {
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
        build: impl FnOnce() -> Option<crate::analyzer::usages::inverted_edges::UsageEdges>,
    ) -> Option<Arc<crate::analyzer::usages::inverted_edges::UsageEdges>> {
        let key = PythonUsageEdgesKey::new(nodes, targets);
        self.usage_edges
            .optionally_get_with(key, || build().map(Arc::new))
    }

    pub(super) fn cached_class_member_mutation_free(
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
        prepared: &crate::analyzer::tree_sitter_analyzer::PreparedSyntaxTree,
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
        crate::analyzer::common::import_target_files_from_cache(
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

use crate::analyzer::CodeUnitIndex;

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
        crate::analyzer::with_query_scope(self, |token| self.import_binder_of(token, file))
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
    ) -> Option<Arc<crate::analyzer::tree_sitter_analyzer::PreparedSyntaxTree>> {
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
        fn prefetch_definitions(&self, fq_names: &[String]);
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

    fn project(&self) -> &dyn Project {
        self.inner.adapter().project()
    }

    fn parent_of(&self, code_unit: &CodeUnit) -> Option<CodeUnit> {
        self.inner.structural_parent_of(code_unit)
    }

    crate::analyzer::tree_sitter_analyzer::delegate_inner_methods! {
        fn get_all_declarations(&self) -> Vec<CodeUnit>;
    }

    fn get_skeleton(&self, code_unit: &CodeUnit) -> Option<String> {
        let mut rendered = String::new();
        render_skeleton_recursive(self, code_unit, "", false, &mut rendered);
        crate::analyzer::common::normalize_skeleton(rendered)
    }

    fn get_skeleton_header(&self, code_unit: &CodeUnit) -> Option<String> {
        let mut rendered = String::new();
        render_skeleton_recursive(self, code_unit, "", true, &mut rendered);
        crate::analyzer::common::normalize_skeleton(rendered)
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
}

impl IAnalyzer for PythonAnalyzer {
    crate::analyzer::tree_sitter_analyzer::delegate_inner_procedure_fact_methods!();

    crate::analyzer::i_analyzer::forward_relational_definition_batch!();

    #[cfg(any(test, feature = "test-support"))]
    fn test_hooks(&self) -> &dyn crate::analyzer::AnalyzerTestHooks {
        self
    }

    crate::analyzer::i_analyzer::forward_file_identity_invalidation!();

    fn working_tree_identity(&self) -> Option<std::sync::Arc<crate::gitblob::WorkingTreeIdentity>> {
        self.inner.working_tree_identity()
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
        Self::from_inner(self.inner.update(changed_files), self.memo_budget)
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
        let scope = AnalyzerQueryScope::new(self);
        diagnostics::collect_python_semantic_diagnostics(self, scope.token(), file, source)
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

    fn type_hierarchy_provider(&self) -> Option<&dyn TypeHierarchyProvider> {
        Some(self)
    }

    fn python_class_hierarchy_provider_for(
        &self,
        _declaration: &CodeUnit,
    ) -> Option<&dyn crate::analyzer::usages::python_class_hierarchy::PythonClassHierarchyProvider>
    {
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
        crate::analyzer::test_assertion_smells_for_file(self, file, Language::Python, |source| {
            detect_python_test_assertion_smells(file, source, &weights)
        })
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
impl crate::analyzer::AnalyzerTestHooks for PythonAnalyzer {
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

impl TestDetectionProvider for PythonAnalyzer {}

static PYTHON_USAGE_STRATEGY: PythonExportUsageGraphStrategy =
    PythonExportUsageGraphStrategy::new();

pub(crate) struct PythonSupport;

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
        crate::analyzer::usages::get_definition::ExactExternalCallProof::python_imported_call(
            canonical_callee,
            parameter_count,
        );
    Some(ImportedExternalCallee::proven(
        proof,
        crate::analyzer::semantic::ResolverOwnedExternalCalleeIdentity::new(
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
        crate::analyzer::usages::receiver_analysis::INTERACTIVE_TYPE_LOOKUP_BUDGET,
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
        != crate::analyzer::semantic_model::SemanticModelOverlayDisposition::Unique
        || symbol.language != Language::Python.config_label()
        || symbol.qualified_name != canonical_callee
        || symbol.kind != crate::analyzer::semantic_model::SemanticModelSymbolKind::Function
        || !symbol.callable_family_complete
        || symbol.provenance.ambiguous
        || symbol.provenance.completeness
            != crate::analyzer::semantic_model::SemanticModelCompleteness::Complete
        || owner_matches.disposition
            != crate::analyzer::semantic_model::SemanticModelOverlayDisposition::Unique
        || owner.language != Language::Python.config_label()
        || owner.kind != crate::analyzer::semantic_model::SemanticModelSymbolKind::Module
        || owner.qualified_name != module
        || symbol.owner_id.as_deref() != Some(owner.id.as_str())
    {
        return None;
    }
    let arguments = call.child_by_field_name("arguments")?;
    let mut cursor = arguments.walk();
    let parameter_count = u32::try_from(arguments.named_children(&mut cursor).count()).ok()?;
    let proof =
        crate::analyzer::usages::get_definition::ExactExternalCallProof::python_imported_call(
            canonical_callee,
            parameter_count,
        );
    Some(ImportedExternalCallee::proven(
        proof,
        crate::analyzer::semantic::ResolverOwnedExternalCalleeIdentity::new(
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
        path: crate::path_utils::rel_path_string(file),
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
        != crate::analyzer::semantic_model::SemanticModelOverlayDisposition::Unique
        || owner.kind != crate::analyzer::semantic_model::SemanticModelSymbolKind::Class
        || owner.language != Language::Python.config_label()
        || owner.qualified_name != receiver_type.fqn
        || owner.provenance.ambiguous
        || owner.provenance.completeness
            != crate::analyzer::semantic_model::SemanticModelCompleteness::Complete
    {
        return None;
    }
    let declaration = python_external_member_declaration(&overlay, &owner.id, member)?;
    if declaration.kind != crate::analyzer::semantic_model::SemanticModelSymbolKind::Method
        || !declaration.has_receiver()
        || !declaration.has_complete_callable_shape_evidence()
        || declaration.structured_signature().is_none()
        || declaration.provenance.ambiguous
        || declaration.provenance.completeness
            != crate::analyzer::semantic_model::SemanticModelCompleteness::Complete
    {
        return None;
    }
    let declaration_owner_id = declaration.owner_id.as_deref()?;
    let declaration_owner_match = overlay.symbols_with_id(declaration_owner_id);
    let [declaration_owner] = declaration_owner_match.records.as_slice() else {
        return None;
    };
    if declaration_owner_match.disposition
        != crate::analyzer::semantic_model::SemanticModelOverlayDisposition::Unique
        || declaration_owner.kind != crate::analyzer::semantic_model::SemanticModelSymbolKind::Class
        || declaration_owner.language != Language::Python.config_label()
        || declaration_owner.provenance.ambiguous
        || declaration_owner.provenance.completeness
            != crate::analyzer::semantic_model::SemanticModelCompleteness::Complete
    {
        return None;
    }
    let arguments = call.child_by_field_name("arguments")?;
    let mut cursor = arguments.walk();
    let parameter_count = u32::try_from(arguments.named_children(&mut cursor).count()).ok()?;
    let proof =
        crate::analyzer::usages::get_definition::ExactExternalCallProof::python_bound_external_member(
            &declaration_owner.qualified_name,
            member,
            parameter_count,
        );
    Some(ImportedExternalCallee::proven(
        proof,
        crate::analyzer::semantic::ResolverOwnedExternalCalleeIdentity::new(
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
            if crate::analyzer::common::language_for_file(file) != Language::Python {
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

    fn keyed_property_reads_container_element(&self) -> bool {
        true
    }

    fn external_field_read_discharges_gap(
        &self,
        workspace: &crate::analyzer::WorkspaceAnalyzer,
        procedure: &crate::analyzer::semantic::ProcedureHandle,
        gap: &crate::analyzer::semantic::SemanticGap,
    ) -> bool {
        type_flow::python_external_field_read_discharges_gap(workspace, procedure, gap)
    }

    fn language(&self) -> Language {
        Language::Python
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
                crate::analyzer::usages::get_definition::ExactExternalCallProof::python_builtin_call(
                    "builtins.print",
                    parameter_count,
                ),
                crate::analyzer::semantic::ResolverOwnedExternalCalleeIdentity::new(
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

    fn procedure_syntax_roles(&self) -> Option<crate::analyzer::languages::ProcedureSyntaxRoles> {
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

    fn is_configuration_input_path(&self, path: &std::path::Path) -> bool {
        matches!(
            path.file_name().and_then(|name| name.to_str()),
            Some("pyproject.toml" | "setup.py" | "__init__.py")
        )
    }

    fn path_synthetic_module_unit(
        &self,
        project: &dyn Project,
        file: &ProjectFile,
    ) -> Option<CodeUnit> {
        use brokk_bifrost_python::declarations::module_code_unit;
        module_code_unit(project, file)
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
        crate::analyzer::languages::with_resolved_analyzer::<PythonAnalyzer, _>(
            analyzer,
            |python| python.ranges_limited(unit, limit),
        )
    }

    fn forward_query_provider<'a>(
        &self,
        analyzer: &'a dyn IAnalyzer,
    ) -> Option<&'a dyn ForwardQueryProvider> {
        crate::analyzer::forward_query_provider::<PythonAnalyzer>(analyzer)
    }

    fn refine_resolved_call_targets(
        &self,
        analyzer: &dyn IAnalyzer,
        token: QueryToken<'_>,
        file: &ProjectFile,
        site: &crate::analyzer::languages::ExternalCalleeSite<'_>,
        targets: &mut [crate::analyzer::usages::call_relations::CallDispatchTarget],
    ) {
        let Some(receiver_class) =
            crate::analyzer::usages::get_definition::python_bound_receiver_class_for_method_call(
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
                target.proof = crate::analyzer::usages::UsageProof::Unproven;
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

    fn reference_usage_strategy(&self) -> &'static dyn crate::analyzer::usages::GraphUsageAnalyzer {
        &PYTHON_USAGE_STRATEGY
    }

    fn reference_graph_backend(&self) -> crate::analyzer::languages::LanguageGraphBackend {
        crate::analyzer::languages::LanguageGraphBackend::Legacy(&PythonEdgePass)
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

    fn type_flow_adapter(&self) -> Option<&'static dyn crate::analyzer::semantic::TypeFlowAdapter> {
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

    fn parser_language(&self, _flavor: crate::analyzer::ParserFlavor) -> tree_sitter::Language {
        tree_sitter_python::LANGUAGE.into()
    }

    fn structural_spec(&self) -> &'static dyn crate::analyzer::structural::StructuralSpec {
        &brokk_bifrost_python::structural::PYTHON_STRUCTURAL_SPEC
    }

    fn highlight_query(&self) -> Option<&'static str> {
        Some(tree_sitter_python::HIGHLIGHTS_QUERY)
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
        crate::analyzer::languages::with_bounded_receiver_query(query, |query, token| {
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
        })
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
