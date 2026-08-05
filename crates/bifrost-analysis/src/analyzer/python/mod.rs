//! The analyzer-owned shim over [`brokk_bifrost_python`].
//!
//! What lives here is everything the language crate cannot name: the
//! [`PythonAnalyzer`] newtype and its six moka caches, two `OnceLock`s and
//! `PoolSafeMemo`; the accessors that implement
//! [`brokk_bifrost_python::graph_support::PythonAnalysisSource`] and
//! [`brokk_bifrost_python::graph_support::PythonUsageSource`] out of them; the
//! `PythonAdapter` forwarding shell; the `IAnalyzer`/`CodeUnitIndex` impls; and
//! the `LanguageSupport` SPI block.

mod adapter;
mod cache;
mod clones;
mod diagnostics;
pub mod external;
mod hierarchy;
mod imports;
pub(crate) mod lexical_scope;
mod semantic;
mod structural;
use crate::analyzer::Range;

pub(crate) use brokk_bifrost_python::syntax::{
    python_deferred_annotation_identifier_ranges, python_node_is_in_annotation,
};

use crate::analyzer::clone_detection::{
    CloneCandidateProfile, detect_structural_clone_smells, refine_clone_similarity_with_ast,
};
use crate::analyzer::common::language_for_file as file_language;
use crate::analyzer::languages::{
    BoundedReceiverQuery, CandidateAugmentation, CandidateCtx, DeadCodeBulkEdges,
    DeadCodeBulkPreflight, DeadCodeBulkProof, DeadCodeRouting, DeadCodeSupport, EdgePassId,
    EdgeSiteScanCtx, EdgeWeightScanCtx, LanguageEdgePass, LanguageEdgeSites, LanguageEdgeWeights,
    LanguageSupport, StructuralReceiverResolver, analyzable_file_count, candidate_fqns,
    fqn_bulk_nodes,
};
use crate::analyzer::store::LimitedQueryRows;
use crate::analyzer::usages::GraphUsageAnalyzer;
use crate::analyzer::usages::get_definition::{
    BoundedResolution, DefinitionLookupOutcome, resolve_python_bounded,
};
use crate::analyzer::usages::get_type::{TypeLookupOutcome, resolve_python_type_bounded};
use crate::analyzer::usages::python_graph::{
    PythonExportUsageGraphStrategy, build_cached_python_usage_edges_for_targets,
    build_python_usage_edge_weights, build_python_usage_edges, python_usage_candidate_files,
};
use crate::analyzer::usages::workspace_graph::UsageEcosystem;
use crate::analyzer::usages::{ExportIndex, ImportBinder};
use crate::analyzer::weighted_cache::{
    build_weighted_cache, weight_code_unit_set, weight_project_file_set,
};
use crate::analyzer::{
    AnalyzerConfig, AnalyzerStoreContext, BuildProgress, BulkFileStateSource, CloneSmell,
    CloneSmellWeights, CodeUnit, DirectDescendantIndex, ForwardQueryProvider, IAnalyzer,
    ImportAnalysisProvider, Language, PoolSafeMemo, Project, ProjectFile, SemanticDiagnostic,
    SignatureMetadata, TestAssertionSmell, TestAssertionWeights, TestDetectionProvider,
    TreeSitterAnalyzer, TypeHierarchyProvider, build_reverse_import_index, resolve_analyzer,
};
use crate::hash::{HashMap, HashSet};
use crate::profiling;
use brokk_bifrost_core::analyzer::prepared_syntax::IndexedFileFacts;
use moka::sync::Cache;
use std::collections::BTreeSet;
use std::sync::{Arc, OnceLock};

pub(crate) use adapter::PythonAdapter;
use brokk_bifrost_python::declarations::python_expanded_comment_start;
pub(crate) use brokk_bifrost_python::graph_support::resolve_module_code_unit;
use brokk_bifrost_python::graph_support::{
    PythonAnalysisSource, PythonUsageSource, compute_export_index_of, import_binder_from_imports,
    render_skeleton_recursive,
};
pub(crate) use brokk_bifrost_python::imports::resolve_fqn_candidates;
use brokk_bifrost_python::imports::resolve_imports_batched;
use brokk_bifrost_python::test_detection::detect_python_test_assertion_smells;
use brokk_bifrost_python::usage_index::PythonUsageIndex;
pub(crate) use brokk_bifrost_python::usage_index::{
    ModuleBindingEvent, ModuleBindingEventKind, ModuleBindingTimeline, PythonScopeFacts,
    usage_importer_files, usage_matching_edges, usage_module_binding_timeline,
    usage_resolve_module_files, usage_scope_facts, usage_seeds,
};
use cache::{
    PythonUsageEdgesKey, weight_code_unit_vec, weight_export_index, weight_python_usage_edges,
};
use clones::build_clone_candidate_data;

pub use brokk_bifrost_python::imports::{
    PythonImportBinding, parse_python_import_bindings, parse_python_import_infos,
};

const FILE_STATE_BATCH_SIZE: usize = 256;

#[derive(Clone)]
pub struct PythonAnalyzer {
    inner: TreeSitterAnalyzer<PythonAdapter>,
    memo_budget: u64,
    imported_code_units: Cache<ProjectFile, Arc<HashSet<CodeUnit>>>,
    // Every source file this file's imports resolve to, keyed on the file itself -- NOT deduped by
    // binding name like `imported_code_units` (a HashMap<String, CodeUnit> would silently drop an
    // import whose binding name collides with another's). `could_import_file` needs the undeduped
    // set to answer "does ANY import here resolve into `target`" without re-resolving every import
    // on every call (previously uncached, called once per (candidate file, target) pair).
    imported_target_files: Cache<ProjectFile, Arc<HashSet<ProjectFile>>>,
    referencing_files: Cache<ProjectFile, Arc<HashSet<ProjectFile>>>,
    // `export_index_of` re-parses `file` from source on every call (it walks re-export chains, not
    // the store-backed `FileState`). `resolve_exported_name`'s re-export BFS calls it once per hop
    // per importing candidate, so on a workspace where many files resolve through a shared re-export
    // chain this was previously O(candidates * chain depth) redundant full-file parses -- invisible
    // while candidate discovery was single-threaded and dominated by slower costs, but the dominant
    // cost once that walk was fixed and parallelized (#1257).
    export_index: Cache<ProjectFile, Arc<ExportIndex>>,
    direct_ancestors: Cache<CodeUnit, Arc<Vec<CodeUnit>>>,
    // Dead-code analysis scans the stable caller domain but resolves a bounded
    // callee target set. Cache that exact pair for warm requests so repeated
    // queries do not reparse the entire Python workspace.
    usage_edges:
        Cache<PythonUsageEdgesKey, Arc<crate::analyzer::usages::inverted_edges::UsageEdges>>,
    direct_descendant_index: Arc<OnceLock<DirectDescendantIndex>>,
    reverse_import_index: Arc<PoolSafeMemo<HashMap<ProjectFile, Arc<HashSet<ProjectFile>>>>>,
    usage_index: Arc<OnceLock<PythonUsageIndex>>,
}

crate::analyzer::impl_forward_query_provider!(PythonAnalyzer);

impl PythonAnalyzer {
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
        let Some(identifier) = fqn.rsplit('.').next().filter(|name| !name.is_empty()) else {
            return LimitedQueryRows::complete(Vec::new(), 0);
        };
        let mut candidates = self
            .inner
            .lookup_non_module_declarations_by_identifier_limited(
                identifier,
                limit,
                continue_query,
            );
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
        let exact_fqn = format!("{owner_fqn}.{name}");
        let mut candidates = self
            .inner
            .lookup_non_module_declarations_by_identifier_limited(name, limit, continue_query);
        if candidates.complete {
            candidates
                .rows
                .retain(|candidate| candidate.fq_name() == exact_fqn);
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

    pub(crate) fn signature_metadata_limited(
        &self,
        code_unit: &CodeUnit,
        limit: usize,
    ) -> LimitedQueryRows<SignatureMetadata> {
        self.inner.signature_metadata_limited(code_unit, limit)
    }

    pub(crate) fn clone_with_project(&self, project: Arc<dyn Project>) -> Self {
        let mut clone = self.clone();
        clone.inner = clone.inner.clone_with_project(project);
        clone.usage_edges = build_weighted_cache(self.memo_budget / 8, weight_python_usage_edges);
        clone
    }

    pub fn new(project: Arc<dyn Project>) -> Self {
        Self::new_with_config(project, AnalyzerConfig::default())
    }

    pub fn new_with_config(project: Arc<dyn Project>, config: AnalyzerConfig) -> Self {
        let memo_budget = config.memo_cache_budget_bytes();
        let inner = TreeSitterAnalyzer::new_with_config(project, PythonAdapter, config);
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
            PythonAdapter,
            config,
            store_context,
            progress,
        )?;
        Ok(Self::from_inner(inner, memo_budget))
    }

    fn from_inner(inner: TreeSitterAnalyzer<PythonAdapter>, memo_budget: u64) -> Self {
        Self {
            inner,
            memo_budget,
            imported_code_units: build_weighted_cache(memo_budget / 4, weight_code_unit_set),
            imported_target_files: build_weighted_cache(memo_budget / 8, weight_project_file_set),
            referencing_files: build_weighted_cache(memo_budget / 8, weight_project_file_set),
            export_index: build_weighted_cache(memo_budget / 8, weight_export_index),
            direct_ancestors: build_weighted_cache(memo_budget / 8, weight_code_unit_vec),
            usage_edges: build_weighted_cache(memo_budget / 8, weight_python_usage_edges),
            direct_descendant_index: Arc::new(OnceLock::new()),
            reverse_import_index: Arc::new(PoolSafeMemo::new()),
            usage_index: Arc::new(OnceLock::new()),
        }
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
        build: impl FnOnce() -> crate::analyzer::usages::inverted_edges::UsageEdges,
    ) -> Arc<crate::analyzer::usages::inverted_edges::UsageEdges> {
        let key = PythonUsageEdgesKey::new(nodes, targets);
        self.usage_edges.get_with(key, || Arc::new(build()))
    }

    #[doc(hidden)]
    pub fn write_live_file_to_store_for_test(&self, file: &ProjectFile) -> Option<()> {
        self.inner.write_live_file_to_store_for_test(file)
    }

    /// The cached re-export/importer index, built once per analyzer generation.
    fn usage_index(&self) -> &PythonUsageIndex {
        self.usage_index
            .get_or_init(|| PythonUsageIndex::build(self))
    }

    /// `get_with` (not get-then-insert): callers include the parallelized candidate walker's
    /// re-export BFS, so two threads racing on the same file's first lookup must not both pay the
    /// full disk-read-and-reparse cost below.
    pub fn export_index_of(&self, file: &ProjectFile) -> ExportIndex {
        self.export_index
            .get_with(file.clone(), || {
                Arc::new(compute_export_index_of(self, file))
            })
            .as_ref()
            .clone()
    }

    pub fn import_binder_of(&self, file: &ProjectFile) -> ImportBinder {
        import_binder_from_imports(self, file, &self.inner.import_info_of(file))
    }

    /// The set of files any of `file`'s imports resolve into, cached per file. Unlike
    /// `resolve_import_bindings` (keyed by binding name, so a name collision drops an entry), this
    /// keeps every resolved target so `could_import_file` can do an exact membership check.
    ///
    /// `get_with` (not get-then-insert): `could_import_file` is called concurrently across worker
    /// threads by the now-parallelized candidate walker, and get-then-insert would let two threads
    /// that both miss the cache for the same file each redundantly pay the whole-file resolution
    /// cost. `get_with` guarantees only one thread ever runs the init closure per key.
    fn resolve_import_target_files(&self, file: &ProjectFile) -> Arc<HashSet<ProjectFile>> {
        self.imported_target_files.get_with(file.clone(), || {
            let imports = self.inner.import_info_of(file);
            let targets: HashSet<ProjectFile> = resolve_imports_batched(self, file, &imports)
                .into_iter()
                .flatten()
                .map(|(_, code_unit)| code_unit.source().clone())
                .collect();
            Arc::new(targets)
        })
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

use crate::analyzer::CodeUnitIndex;

impl PythonAnalysisSource for PythonAnalyzer {
    fn path_module_fqn(&self, module_fq: &str) -> Option<Vec<CodeUnit>> {
        self.inner.forward_path_module_fqn(module_fq)
    }

    fn path_module_fqns_batch(&self, module_fqs: &[String]) -> Vec<Option<Vec<CodeUnit>>> {
        self.inner.forward_path_module_fqns_batch(module_fqs)
    }

    fn definition_fqn(&self, fqn: &str) -> Vec<CodeUnit> {
        self.inner.forward_definition_fqn(fqn)
    }

    fn import_binder_of(&self, file: &ProjectFile) -> ImportBinder {
        self.import_binder_of(file)
    }

    fn export_index_of(&self, file: &ProjectFile) -> ExportIndex {
        self.export_index_of(file)
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
    fn usage_index(&self) -> &PythonUsageIndex {
        self.usage_index()
    }
}

impl CodeUnitIndex for PythonAnalyzer {
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

    fn get_all_declarations(&self) -> Vec<CodeUnit> {
        self.inner.get_all_declarations()
    }

    fn get_definitions(&self, fq_name: &str) -> Vec<CodeUnit> {
        self.inner.get_definitions(fq_name)
    }

    fn get_skeleton(&self, code_unit: &CodeUnit) -> Option<String> {
        let mut rendered = String::new();
        render_skeleton_recursive(self, code_unit, "", false, &mut rendered);
        let trimmed = rendered.trim_end();
        (!trimmed.is_empty()).then(|| trimmed.to_string())
    }

    fn get_skeleton_header(&self, code_unit: &CodeUnit) -> Option<String> {
        let mut rendered = String::new();
        render_skeleton_recursive(self, code_unit, "", true, &mut rendered);
        let trimmed = rendered.trim_end();
        (!trimmed.is_empty()).then(|| trimmed.to_string())
    }

    fn get_source(&self, code_unit: &CodeUnit, include_comments: bool) -> Option<String> {
        let sources = self.get_sources(code_unit, include_comments);
        if sources.is_empty() {
            None
        } else {
            Some(sources.into_iter().collect::<Vec<_>>().join("\n\n"))
        }
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

        let Ok(source) = self.inner.project().read_source(code_unit.source()) else {
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

impl IAnalyzer for PythonAnalyzer {
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
        Self {
            inner,
            memo_budget: self.memo_budget,
            imported_code_units: build_weighted_cache(self.memo_budget / 4, weight_code_unit_set),
            imported_target_files: build_weighted_cache(
                self.memo_budget / 8,
                weight_project_file_set,
            ),
            referencing_files: build_weighted_cache(self.memo_budget / 8, weight_project_file_set),
            export_index: build_weighted_cache(self.memo_budget / 8, weight_export_index),
            direct_ancestors: build_weighted_cache(self.memo_budget / 8, weight_code_unit_vec),
            usage_edges: build_weighted_cache(self.memo_budget / 8, weight_python_usage_edges),
            direct_descendant_index: Arc::new(OnceLock::new()),
            reverse_import_index: Arc::new(PoolSafeMemo::new()),
            usage_index: Arc::new(OnceLock::new()),
        }
    }

    fn update_all(&self) -> Self {
        let inner = self.inner.update_all();
        Self {
            inner,
            memo_budget: self.memo_budget,
            imported_code_units: build_weighted_cache(self.memo_budget / 4, weight_code_unit_set),
            imported_target_files: build_weighted_cache(
                self.memo_budget / 8,
                weight_project_file_set,
            ),
            referencing_files: build_weighted_cache(self.memo_budget / 8, weight_project_file_set),
            export_index: build_weighted_cache(self.memo_budget / 8, weight_export_index),
            direct_ancestors: build_weighted_cache(self.memo_budget / 8, weight_code_unit_vec),
            usage_edges: build_weighted_cache(self.memo_budget / 8, weight_python_usage_edges),
            direct_descendant_index: Arc::new(OnceLock::new()),
            reverse_import_index: Arc::new(PoolSafeMemo::new()),
            usage_index: Arc::new(OnceLock::new()),
        }
    }

    fn parse_errors(&self, file: &ProjectFile) -> Option<Vec<crate::analyzer::ParseError>> {
        self.inner.parse_errors(file)
    }

    fn semantic_diagnostics(&self, file: &ProjectFile, source: &str) -> Vec<SemanticDiagnostic> {
        diagnostics::collect_python_semantic_diagnostics(self, file, source)
            .into_iter()
            .map(Into::into)
            .collect()
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

    fn type_hierarchy_provider(&self) -> Option<&dyn TypeHierarchyProvider> {
        Some(self)
    }

    fn test_detection_provider(&self) -> Option<&dyn TestDetectionProvider> {
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
        if !self.contains_tests(file) || file_language(file) != Language::Python {
            return Vec::new();
        }
        let Ok(source) = self.inner.project().read_source(file) else {
            return Vec::new();
        };
        detect_python_test_assertion_smells(file, &source, &weights)
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
            .filter(|file| file_language(file) == Language::Python)
            .cloned()
            .collect();
        if requested_files.is_empty() {
            return Vec::new();
        }

        let all_candidates: Vec<CloneCandidateProfile> = self
            .get_all_declarations()
            .into_iter()
            .filter(|code_unit| {
                code_unit.is_function() && file_language(code_unit.source()) == Language::Python
            })
            .filter_map(|code_unit| build_clone_candidate_data(self, &code_unit, weights))
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
impl crate::analyzer::AnalyzerTestHooks for PythonAnalyzer {
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

impl TestDetectionProvider for PythonAnalyzer {}

static PYTHON_USAGE_STRATEGY: PythonExportUsageGraphStrategy =
    PythonExportUsageGraphStrategy::new();

pub(crate) struct PythonSupport;

impl LanguageSupport for PythonSupport {
    fn language(&self) -> Language {
        Language::Python
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

    fn declaration_ranges_limited(
        &self,
        analyzer: &dyn IAnalyzer,
        unit: &CodeUnit,
        limit: usize,
    ) -> Option<LimitedQueryRows<Range>> {
        resolve_analyzer::<PythonAnalyzer>(analyzer)
            .map(|python| python.ranges_limited(unit, limit))
    }

    fn forward_query_provider<'a>(
        &self,
        analyzer: &'a dyn IAnalyzer,
    ) -> Option<&'a dyn ForwardQueryProvider> {
        resolve_analyzer::<PythonAnalyzer>(analyzer).map(|value| value as _)
    }

    fn ecosystem(&self) -> UsageEcosystem {
        UsageEcosystem::Python
    }

    fn usage_strategy(&self) -> &'static dyn GraphUsageAnalyzer {
        &PYTHON_USAGE_STRATEGY
    }

    fn edge_pass(&self) -> Option<&'static dyn LanguageEdgePass> {
        Some(&PythonEdgePass)
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
        build_python_usage_edges(ctx.analyzer, ctx.fqns, ctx.keep_file).map(LanguageEdgeSites)
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
        resolve_python_type_bounded(
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
        resolve_python_bounded(
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

struct PythonDeadCodeBulk;

impl DeadCodeBulkProof for PythonDeadCodeBulk {
    fn id(&self) -> EdgePassId {
        EdgePassId::Python
    }

    fn needs_precise_scan(&self, _routing: DeadCodeRouting<'_>) -> bool {
        false
    }

    fn preflight(&self, analyzer: &dyn IAnalyzer) -> DeadCodeBulkPreflight {
        DeadCodeBulkPreflight::Ready {
            label: "Python",
            files: analyzable_file_count(analyzer, Language::Python),
        }
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
