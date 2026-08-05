mod adapter;
mod cache;
mod cargo_routes;
mod clones;
mod declarations;
mod dependency_discovery;
mod diagnostics;
mod external;
pub(crate) mod field_roles;
mod graph_support;
mod hierarchy;
mod imports;
pub(crate) mod lexical_scope;
mod rustdoc_artifact;
mod semantic;
pub(crate) mod structural;
mod tests;
mod usage_index;

use crate::analyzer::clone_detection::detect_language_structural_clone_smells;
use crate::analyzer::common::language_for_file as file_language;
use crate::analyzer::store::LimitedQueryRows;
use crate::analyzer::type_relations::TypeRelation;
use crate::analyzer::{
    AnalyzerConfig, AnalyzerStoreContext, BuildProgress, CloneSmell, CloneSmellWeights, CodeUnit,
    IAnalyzer, ImportAnalysisProvider, Language, PoolSafeMemo, Project, ProjectFile, Range,
    SignatureMetadata, TestAssertionSmell, TestAssertionWeights, TestDetectionProvider,
    TreeSitterAnalyzer, TypeAliasProvider, TypeHierarchyProvider,
};
use crate::hash::{HashMap, HashSet};
use moka::sync::Cache;
use std::collections::BTreeSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use tree_sitter::Parser;

use super::js_ts::build_weighted_cache;
pub(crate) use adapter::RustAdapter;
use cache::{
    weight_code_unit_set, weight_export_index, weight_project_file_set, weight_reference_context,
};
use cargo_routes::{RustCargoRouteIndex, RustCargoTargetRelation};
use clones::build_rust_clone_candidate_data;
use declarations::collect_rust_type_identifiers;
pub(crate) use declarations::rust_package_name;
pub use dependency_discovery::resolve_rust_semantic_pack_dependencies;
pub use external::RustDependencyPackAdapter;
pub use field_roles::rust_is_field_declaration_name;
pub(crate) use imports::{
    resolve_rust_import_package_scoped, resolve_rust_module_segments_with_crate,
    rust_crate_root_package, rust_focused_use_path,
};
pub use rustdoc_artifact::RustdocJsonPackProducer;
use tests::detect_rust_test_assertion_smells;

use graph_support::RustPackageFileIndex;
pub use graph_support::RustReferenceContext;

use hierarchy::RustHierarchyIndex;
pub use lexical_scope::{
    reset_rust_tree_parse_counters_for_test, rust_tree_parse_count_for_test,
    rust_tree_parse_request_count_for_test, rust_tree_parsed_bytes_for_test,
};
use usage_index::RustUsageIndex;
pub(crate) use usage_index::{RustBindingSeeds, RustReferenceNamespace};

#[derive(Clone)]
pub struct RustAnalyzer {
    inner: TreeSitterAnalyzer<RustAdapter>,
    memo_budget: u64,
    imported_code_units: Cache<ProjectFile, Arc<HashSet<CodeUnit>>>,
    referencing_files: Cache<ProjectFile, Arc<HashSet<ProjectFile>>>,
    reference_contexts: Cache<ProjectFile, Arc<RustReferenceContext>>,
    forward_reference_contexts: Cache<ProjectFile, Arc<RustReferenceContext>>,
    export_indexes: Cache<ProjectFile, Arc<crate::analyzer::usages::ExportIndex>>,
    reverse_import_index: Arc<PoolSafeMemo<HashMap<ProjectFile, Arc<HashSet<ProjectFile>>>>>,
    // PoolSafeMemo, not OnceLock: the build hydrates and parses every file on
    // rayon, and this cache is reached from inside rayon workers (see
    // `pool_memo`). A blocking get_or_init there can deadlock the pool.
    cargo_routes: Arc<PoolSafeMemo<RustCargoRouteIndex>>,
    package_file_index: Arc<OnceLock<Arc<RustPackageFileIndex>>>,
    /// `resolve_module_files` calls. A use-path's module files are invariant in
    /// the export name being resolved, so this count is what proves the
    /// per-export-name recomputation is gone (#1230 item 4).
    module_file_resolution_count: Arc<AtomicUsize>,
    usage_index: Arc<PoolSafeMemo<RustUsageIndex>>,
    hierarchy_index: Arc<OnceLock<RustHierarchyIndex>>,
    #[allow(dead_code)]
    type_relations: Arc<OnceLock<Vec<TypeRelation>>>,
}

crate::analyzer::impl_forward_query_provider!(RustAnalyzer);

impl RustAnalyzer {
    pub(crate) fn structural_parent_of(&self, code_unit: &CodeUnit) -> Option<CodeUnit> {
        self.inner.structural_parent_of(code_unit)
    }

    pub(crate) fn prepared_syntax(
        &self,
        file: &ProjectFile,
    ) -> Option<Arc<crate::analyzer::tree_sitter_analyzer::PreparedSyntaxTree>> {
        self.inner.prepared_syntax(file)
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
        let exact_fqn = format!("{owner_fqn}.{name}");
        self.declaration_candidates_by_fqn_limited(&exact_fqn, limit, continue_query)
    }

    pub(crate) fn signature_metadata_limited(
        &self,
        code_unit: &CodeUnit,
        limit: usize,
    ) -> LimitedQueryRows<SignatureMetadata> {
        self.inner.signature_metadata_limited(code_unit, limit)
    }

    pub(crate) fn ranges_limited(
        &self,
        code_unit: &CodeUnit,
        limit: usize,
    ) -> LimitedQueryRows<Range> {
        self.inner.ranges_limited(code_unit, limit)
    }

    #[cfg(test)]
    pub(crate) fn prepared_syntax_parse_count_for_test(&self, file: &ProjectFile) -> usize {
        self.inner.prepared_syntax_parse_count_for_test(file)
    }

    /// Per-instance counters behind the #1230 complexity pins. Each is shared by
    /// `Clone` (so a cloned analyzer keeps counting into the same cell) and
    /// reset by the analyzer that owns it, never process-globally, so suites
    /// running in parallel cannot bleed into one another.
    pub(super) fn note_module_file_resolution(&self) {
        self.module_file_resolution_count
            .fetch_add(1, Ordering::Relaxed);
    }

    #[doc(hidden)]
    pub fn reset_module_file_resolution_count_for_test(&self) {
        self.module_file_resolution_count
            .store(0, Ordering::Relaxed);
    }

    #[doc(hidden)]
    pub fn module_file_resolution_count_for_test(&self) -> usize {
        self.module_file_resolution_count.load(Ordering::Relaxed)
    }

    #[doc(hidden)]
    pub fn reset_analyzed_file_listing_count_for_test(&self) {
        self.inner.reset_analyzed_file_listing_count_for_test();
    }

    #[doc(hidden)]
    pub fn analyzed_file_listing_count_for_test(&self) -> usize {
        self.inner.analyzed_file_listing_count_for_test()
    }

    #[doc(hidden)]
    pub fn reset_definition_candidates_query_count_for_test(&self) {
        self.inner
            .reset_definition_candidates_query_count_for_test();
    }

    #[doc(hidden)]
    pub fn definition_candidates_query_count_for_test(&self) -> usize {
        self.inner.definition_candidates_query_count_for_test()
    }

    fn indexed_sources_unchanged(&self, changed_files: &BTreeSet<ProjectFile>) -> bool {
        changed_files
            .iter()
            .filter(|file| file_language(file) == Language::Rust || self.inner.is_analyzed(file))
            .all(|file| {
                self.inner
                    .project()
                    .read_source(file)
                    .ok()
                    .is_some_and(|source| self.inner.indexed_source_matches(file, &source))
            })
    }

    pub(crate) fn clone_with_project(&self, project: Arc<dyn Project>) -> Self {
        let mut clone = self.clone();
        clone.inner = clone.inner.clone_with_project(project);
        clone.cargo_routes = Arc::new(PoolSafeMemo::new());
        clone.package_file_index = Arc::new(OnceLock::new());
        clone
    }

    /// Explicit inverse-analysis support. Forward definition and type queries
    /// resolve only the importing file's manifest route.
    fn cargo_routes(&self) -> Arc<RustCargoRouteIndex> {
        self.cargo_routes.get_or_build(
            || self.build_cargo_routes(true),
            || self.build_cargo_routes(false),
        )
    }

    fn cargo_routes_while(
        &self,
        keep_going: &(impl Fn() -> bool + Sync),
    ) -> Option<Arc<RustCargoRouteIndex>> {
        self.cargo_routes.get_or_build_while(
            keep_going,
            || self.build_cargo_routes_while(true, keep_going),
            || self.build_cargo_routes_while(false, keep_going),
        )
    }

    fn build_cargo_routes(&self, parallel: bool) -> RustCargoRouteIndex {
        self.build_cargo_routes_while(parallel, &|| true)
            .expect("uninterrupted Rust Cargo-route construction")
    }

    fn build_cargo_routes_while(
        &self,
        parallel: bool,
        keep_going: &(impl Fn() -> bool + Sync),
    ) -> Option<RustCargoRouteIndex> {
        let files: Vec<_> = self.get_analyzed_files().into_iter().collect();
        RustCargoRouteIndex::build_while(
            &files,
            |file| self.prepared_syntax(file),
            parallel,
            keep_going,
        )
    }

    #[cfg(test)]
    pub(crate) fn cargo_routes_ready_for_test(&self) -> bool {
        self.cargo_routes.is_ready()
    }

    pub(crate) fn candidates_in_same_cargo_target_root(
        &self,
        file: &ProjectFile,
        candidates: Vec<CodeUnit>,
    ) -> Option<Vec<CodeUnit>> {
        self.cargo_routes()
            .candidates_in_same_target_root(file, candidates)
    }

    pub(crate) fn cargo_target_roots_for_file(&self, file: &ProjectFile) -> Vec<ProjectFile> {
        self.cargo_routes().target_roots_for_file(file)
    }

    pub(crate) fn file_uses_rust_2015_edition(&self, file: &ProjectFile) -> bool {
        self.cargo_routes().file_uses_rust_2015_edition(file)
    }

    pub(crate) fn has_available_declared_cargo_dependency(
        &self,
        file: &ProjectFile,
        route: &str,
    ) -> bool {
        self.cargo_routes()
            .has_available_declared_dependency(file, route)
    }

    pub(crate) fn files_share_cargo_target(
        &self,
        left: &ProjectFile,
        right: &ProjectFile,
    ) -> Option<bool> {
        match self.cargo_routes().target_relation(left, right) {
            RustCargoTargetRelation::Shared => Some(true),
            RustCargoTargetRelation::Disjoint => Some(false),
            RustCargoTargetRelation::Unknown => None,
        }
    }

    pub(crate) fn candidates_in_cargo_library_route(
        &self,
        file: &ProjectFile,
        route: &str,
        candidates: Vec<CodeUnit>,
    ) -> Option<Vec<CodeUnit>> {
        self.cargo_routes()
            .candidates_in_library_route(file, route, candidates)
    }

    pub(crate) fn resolve_cargo_crate_root_file(
        &self,
        file: &ProjectFile,
        route: &str,
    ) -> Option<ProjectFile> {
        self.cargo_routes().resolve_crate_root_file(file, route)
    }

    pub fn new(project: Arc<dyn Project>) -> Self {
        Self::new_with_config(project, AnalyzerConfig::default())
    }

    pub fn new_with_config(project: Arc<dyn Project>, config: AnalyzerConfig) -> Self {
        let memo_budget = config.memo_cache_budget_bytes();
        Self {
            inner: TreeSitterAnalyzer::new_with_config(project, RustAdapter, config),
            memo_budget,
            imported_code_units: build_weighted_cache(memo_budget / 4, weight_code_unit_set),
            referencing_files: build_weighted_cache(memo_budget / 8, weight_project_file_set),
            reference_contexts: build_weighted_cache(memo_budget / 8, weight_reference_context),
            forward_reference_contexts: build_weighted_cache(
                memo_budget / 8,
                weight_reference_context,
            ),
            export_indexes: build_weighted_cache(memo_budget / 8, weight_export_index),
            reverse_import_index: Arc::new(PoolSafeMemo::new()),
            cargo_routes: Arc::new(PoolSafeMemo::new()),
            package_file_index: Arc::new(OnceLock::new()),
            module_file_resolution_count: Arc::new(AtomicUsize::new(0)),
            usage_index: Arc::new(PoolSafeMemo::new()),
            hierarchy_index: Arc::new(OnceLock::new()),
            type_relations: Arc::new(OnceLock::new()),
        }
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
            RustAdapter,
            config,
            store_context,
            progress,
        )?;
        Ok(Self {
            inner,
            memo_budget,
            imported_code_units: build_weighted_cache(memo_budget / 4, weight_code_unit_set),
            referencing_files: build_weighted_cache(memo_budget / 8, weight_project_file_set),
            reference_contexts: build_weighted_cache(memo_budget / 8, weight_reference_context),
            forward_reference_contexts: build_weighted_cache(
                memo_budget / 8,
                weight_reference_context,
            ),
            export_indexes: build_weighted_cache(memo_budget / 8, weight_export_index),
            reverse_import_index: Arc::new(PoolSafeMemo::new()),
            cargo_routes: Arc::new(PoolSafeMemo::new()),
            package_file_index: Arc::new(OnceLock::new()),
            module_file_resolution_count: Arc::new(AtomicUsize::new(0)),
            usage_index: Arc::new(PoolSafeMemo::new()),
            hierarchy_index: Arc::new(OnceLock::new()),
            type_relations: Arc::new(OnceLock::new()),
        })
    }

    pub fn from_project<P>(project: P) -> Self
    where
        P: Project + 'static,
    {
        Self::new(Arc::new(project))
    }

    pub fn is_type_alias(&self, code_unit: &CodeUnit) -> bool {
        self.inner.is_type_alias(code_unit)
    }

    pub fn extract_type_identifiers(&self, source: &str) -> BTreeSet<String> {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("failed to load rust parser");
        let Some(tree) = parser.parse(source, None) else {
            return BTreeSet::new();
        };
        let mut identifiers = HashSet::default();
        collect_rust_type_identifiers(tree.root_node(), source, &mut identifiers);
        identifiers.into_iter().collect()
    }
}

impl TypeAliasProvider for RustAnalyzer {
    fn is_type_alias(&self, code_unit: &CodeUnit) -> bool {
        self.inner.is_type_alias(code_unit)
    }
}

impl TestDetectionProvider for RustAnalyzer {}

impl IAnalyzer for RustAnalyzer {
    fn invalidate_cached_file_identities(&self) {
        self.inner.invalidate_cached_file_identities();
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

    fn global_usage_definition_index(&self) -> crate::analyzer::DefinitionIndexHandle<'_> {
        self.inner.global_usage_definition_index()
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

    fn reset_search_candidate_hydration_count_for_test(&self) {
        self.inner.reset_search_candidate_hydration_count_for_test();
    }

    fn search_candidate_hydration_count_for_test(&self) -> usize {
        self.inner.search_candidate_hydration_count_for_test()
    }

    fn reset_candidate_hydration_count_for_test(&self) {
        self.inner.reset_full_hydration_count_for_test();
    }

    fn candidate_hydration_count_for_test(&self) -> usize {
        self.inner.full_hydration_count_for_test() + self.inner.bulk_hydration_count_for_test()
    }

    fn full_candidate_hydration_count_for_test(&self) -> usize {
        self.inner.full_hydration_count_for_test()
    }

    fn bulk_candidate_hydration_count_for_test(&self) -> usize {
        self.inner.bulk_hydration_count_for_test()
    }

    fn direct_children(&self, code_unit: &CodeUnit) -> Vec<CodeUnit> {
        self.inner.direct_children(code_unit)
    }

    /// The same owner lookup as the [`IAnalyzer::parent_of`] default plus Rust's
    /// structural fallback, routed through the request-scoped owner memo so a
    /// file of N declarations asking for the same owner name costs one store
    /// query rather than N (#1230 item 6).
    fn parent_of(&self, code_unit: &CodeUnit) -> Option<CodeUnit> {
        self.inner
            .definition_parent_unit(code_unit)
            .or_else(|| self.inner.structural_parent_of(code_unit))
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

    fn abstract_member_implementations(&self, code_unit: &CodeUnit) -> Option<Vec<CodeUnit>> {
        self.rust_trait_member_implementations(code_unit)
    }

    fn get_analyzed_files(&self) -> BTreeSet<ProjectFile> {
        self.inner.get_analyzed_files()
    }

    fn languages(&self) -> BTreeSet<Language> {
        self.inner.languages()
    }

    /// The type-hierarchy and usage indexes each take double-digit seconds to
    /// build on large workspaces; every other lazy cache on this analyzer
    /// fills incrementally at acceptable cost. Warm them sequentially from
    /// the calling thread rather than under `rayon::join`: each build
    /// parallelizes internally, and running the accessors on pool workers
    /// would both demote the usage build to its serial pool-safe path and
    /// block a worker inside the hierarchy `OnceLock` init.
    fn warm_query_indexes(&self) {
        self.hierarchy_index();
        self.usage_index();
    }

    fn query_indexes_warm(&self) -> bool {
        self.hierarchy_index.get().is_some() && self.usage_index.is_ready()
    }

    fn update(&self, changed_files: &BTreeSet<ProjectFile>) -> Self {
        if self.indexed_sources_unchanged(changed_files) {
            return self.clone();
        }

        Self {
            inner: self.inner.update(changed_files),
            memo_budget: self.memo_budget,
            imported_code_units: build_weighted_cache(self.memo_budget / 4, weight_code_unit_set),
            referencing_files: build_weighted_cache(self.memo_budget / 8, weight_project_file_set),
            reference_contexts: build_weighted_cache(
                self.memo_budget / 8,
                weight_reference_context,
            ),
            forward_reference_contexts: build_weighted_cache(
                self.memo_budget / 8,
                weight_reference_context,
            ),
            export_indexes: build_weighted_cache(self.memo_budget / 8, weight_export_index),
            reverse_import_index: Arc::new(PoolSafeMemo::new()),
            cargo_routes: Arc::new(PoolSafeMemo::new()),
            package_file_index: Arc::new(OnceLock::new()),
            module_file_resolution_count: Arc::new(AtomicUsize::new(0)),
            usage_index: Arc::new(PoolSafeMemo::new()),
            hierarchy_index: Arc::new(OnceLock::new()),
            type_relations: Arc::new(OnceLock::new()),
        }
    }

    fn update_all(&self) -> Self {
        Self {
            inner: self.inner.update_all(),
            memo_budget: self.memo_budget,
            imported_code_units: build_weighted_cache(self.memo_budget / 4, weight_code_unit_set),
            referencing_files: build_weighted_cache(self.memo_budget / 8, weight_project_file_set),
            reference_contexts: build_weighted_cache(
                self.memo_budget / 8,
                weight_reference_context,
            ),
            forward_reference_contexts: build_weighted_cache(
                self.memo_budget / 8,
                weight_reference_context,
            ),
            export_indexes: build_weighted_cache(self.memo_budget / 8, weight_export_index),
            reverse_import_index: Arc::new(PoolSafeMemo::new()),
            cargo_routes: Arc::new(PoolSafeMemo::new()),
            package_file_index: Arc::new(OnceLock::new()),
            module_file_resolution_count: Arc::new(AtomicUsize::new(0)),
            usage_index: Arc::new(PoolSafeMemo::new()),
            hierarchy_index: Arc::new(OnceLock::new()),
            type_relations: Arc::new(OnceLock::new()),
        }
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

    fn parse_errors(&self, file: &ProjectFile) -> Option<Vec<crate::analyzer::ParseError>> {
        self.inner.parse_errors(file)
    }

    fn semantic_diagnostics(
        &self,
        file: &ProjectFile,
        source: &str,
    ) -> crate::analyzer::SemanticDiagnosticReport {
        let diagnostics = diagnostics::collect_rust_semantic_diagnostics(self, file, source)
            .into_iter()
            .map(Into::into)
            .collect();
        crate::analyzer::SemanticDiagnosticReport::from_workspace_absences(file, diagnostics)
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

    fn test_detection_provider(&self) -> Option<&dyn TestDetectionProvider> {
        Some(self)
    }

    fn contains_tests(&self, file: &ProjectFile) -> bool {
        self.inner.contains_tests(file)
    }

    /// Per-declaration taint, widened by the file-level verdict: every
    /// declaration in a `#[cfg(test)]`-only module is in a test region, even
    /// the plain helper functions that carry no attribute of their own (#1546).
    fn in_test_region(&self, code_unit: &crate::analyzer::CodeUnit) -> bool {
        self.inner.in_test_region(code_unit) || self.file_is_test_only(code_unit.source())
    }

    fn file_is_test_only(&self, file: &ProjectFile) -> bool {
        self.cargo_routes().file_is_test_only(file)
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
        detect_language_structural_clone_smells(self, files, weights, Language::Rust, |code_unit| {
            build_rust_clone_candidate_data(self, code_unit, weights)
        })
    }

    fn find_test_assertion_smells(
        &self,
        file: &ProjectFile,
        weights: TestAssertionWeights,
    ) -> Vec<TestAssertionSmell> {
        if !self.contains_tests(file) || file_language(file) != Language::Rust {
            return Vec::new();
        }
        let Ok(source) = self.inner.project().read_source(file) else {
            return Vec::new();
        };
        detect_rust_test_assertion_smells(file, &source, &weights)
    }
}
