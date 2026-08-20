mod adapter;
mod cache;
mod cargo_routes;
mod clones;
pub(crate) mod crate_identity;
mod dependency_discovery;
pub(crate) mod diagnostics;
mod external;
mod fact_catch_up;
mod graph_support;
mod hierarchy;
mod imports;
mod rustdoc_artifact;
mod semantic;
mod structural;
#[cfg(test)]
mod usage_queries_tests;
#[cfg(test)]
mod usage_tests;
#[cfg(test)]
mod usage_walks_tests;

use crate::analyzer::QueryToken;
use crate::analyzer::clone_detection::detect_language_structural_clone_smells;
use crate::analyzer::common::language_for_file as file_language;
use crate::analyzer::languages::{
    BoundedReceiverQuery, DeadCodeBulkEdges, DeadCodeBulkPreflight, DeadCodeBulkProof,
    DeadCodeRouting, DeadCodeSupport, EdgePassId, EdgeSiteScanCtx, EdgeWeightScanCtx,
    LanguageEdgePass, LanguageEdgeSites, LanguageEdgeWeights, LanguageSupport,
    StructuralReceiverResolver, fqn_bulk_nodes,
};
use crate::analyzer::store::LimitedQueryRows;
use crate::analyzer::type_relations::TypeRelation;
use crate::analyzer::usages::GraphUsageAnalyzer;
use crate::analyzer::usages::get_definition::{
    BoundedResolution, DefinitionLookupOutcome, resolve_rust_bounded,
};
use crate::analyzer::usages::get_type::{TypeLookupOutcome, resolve_rust_type_bounded};
use crate::analyzer::usages::rust_graph::{
    RustExportUsageGraphStrategy, build_rust_usage_edge_weights, build_rust_usage_edges,
};
use crate::analyzer::usages::workspace_graph::UsageEcosystem;
use crate::analyzer::{
    AnalyzerConfig, AnalyzerStoreContext, BuildProgress, CloneSmell, CloneSmellWeights, CodeUnit,
    ForwardQueryProvider, IAnalyzer, ImportAnalysisProvider, Language, PoolSafeMemo, Project,
    ProjectFile, Range, SignatureMetadata, TestAssertionSmell, TestAssertionWeights,
    TestDetectionProvider, TreeSitterAnalyzer, TypeAliasProvider, TypeHierarchyProvider,
    resolve_analyzer,
};
use crate::analyzer::{AnalyzerQueryScope, QueryScope};
use crate::hash::{HashMap, HashSet};
use moka::sync::Cache;
use std::collections::BTreeSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};

use super::weighted_cache::{build_weighted_cache, weight_code_unit_set, weight_project_file_set};
pub(crate) use adapter::RustAdapter;
use brokk_bifrost_core::analyzer::rust_facts::{RustModuleRouteFacts, RustUsageFacts};
use brokk_bifrost_rust::cache::{weight_declaration_facts, weight_rust_usage_facts};
use brokk_bifrost_rust::graph_support::{RustFactSource, RustLiveBlobs};
use brokk_bifrost_rust::usage_queries::RustDeclarationFacts;
use brokk_bifrost_rust::usage_walks::RustWalkCaches;

/// The key of the per-blob fact cache: the rows are content-addressed, and the
/// generation component retires the whole cache when extraction semantics move.
type RustFactCacheKey = (Option<crate::analyzer::store::GenerationId>, git2::Oid);
use brokk_bifrost_rust::cargo_routes::{RustCargoRouteIndex, RustCargoTargetRelation};
pub(crate) use brokk_bifrost_rust::declarations::{rust_package_name, rust_type_identifiers};
pub use brokk_bifrost_rust::field_roles::rust_is_field_declaration_name;
pub use brokk_bifrost_rust::graph::ast::rust_reference_namespace;
pub(crate) use brokk_bifrost_rust::imports::{
    resolve_rust_import_package_scoped, resolve_rust_module_segments_with_crate,
    rust_crate_root_package, rust_focused_use_path,
};
use brokk_bifrost_rust::test_detection::detect_rust_test_assertion_smells;
use cache::weight_export_index;
use clones::build_rust_clone_candidate_data;
pub use dependency_discovery::resolve_rust_semantic_pack_dependencies;
pub use external::RustDependencyPackAdapter;
pub use rustdoc_artifact::RustdocJsonPackProducer;

use brokk_bifrost_rust::graph_support::RustPackageFileIndex;
pub use brokk_bifrost_rust::graph_support::RustReferenceContext;
use brokk_bifrost_rust::graph_support::is_rust_enum_variant_declaration;
pub(crate) use brokk_bifrost_rust::graph_support::{
    forward_export_fqn_from_files, has_rust_value_constructor, is_rust_const_or_static_declaration,
    is_rust_enum_declaration, is_rust_public_like_declaration, is_rust_trait_declaration,
    is_rust_trait_impl_member_declaration, resolve_imported_export_from_binder_forward,
    resolve_module_files, resolve_module_package, resolve_visible_import_targets_forward,
    rust_associated_type_declaration_for_exact_node, trait_implementer_names,
};

use brokk_bifrost_rust::hierarchy::RustHierarchyIndex;
pub(crate) use brokk_bifrost_rust::hierarchy::canonical_rust_hierarchy_type;
#[cfg(any(test, feature = "test-support"))]
pub use brokk_bifrost_rust::lexical_scope::{
    reset_rust_tree_parse_counters_for_test, rust_tree_parse_count_for_test,
    rust_tree_parse_request_count_for_test, rust_tree_parsed_bytes_for_test,
};
pub use brokk_bifrost_rust::usage::RustReferenceNamespace;
use brokk_bifrost_rust::usage::RustSymbolNamespace;
pub(crate) use brokk_bifrost_rust::usage::{
    RustBindingSeeds, usage_binding_local_names, usage_binding_names, usage_binding_seeds,
    usage_binding_seeds_while, usage_candidate_files_from_binding_seeds_while,
    usage_crate_export_targets, usage_declaration_visible_at, usage_exact_root_for_resolution,
    usage_has_exact_scoped_binding, usage_identity_visible_at, usage_importers,
    usage_local_module_prefix_visible_at, usage_reference_at, usage_root_declaration_matches_at,
};

pub fn rust_declaration_matches_reference_namespace(
    rust: &RustAnalyzer,
    declaration: &CodeUnit,
    reference: RustReferenceNamespace,
) -> bool {
    RustSymbolNamespace::of(rust, declaration)
        .is_some_and(|symbol_namespace| symbol_namespace.accepts(reference))
}

pub fn rust_declaration_is_enum_variant(rust: &RustAnalyzer, declaration: &CodeUnit) -> bool {
    is_rust_enum_variant_declaration(rust, declaration)
}

#[derive(Clone)]
pub struct RustAnalyzer {
    inner: TreeSitterAnalyzer<RustAdapter>,
    memo_budget: u64,
    imported_code_units: Cache<ProjectFile, Arc<HashSet<CodeUnit>>>,
    referencing_files: Cache<ProjectFile, Arc<HashSet<ProjectFile>>>,
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
    export_name_canonicalization_count: Arc<AtomicUsize>,
    scanned_candidate_file_count: Arc<AtomicUsize>,
    usage_binding_seed_preparation_count: Arc<AtomicUsize>,
    /// Files the Cargo-route build had to parse because their blob carried no
    /// persisted module-route rows (#1793).
    module_route_fact_fallback_count: Arc<AtomicUsize>,
    /// One blob's persisted per-file Rust usage facts. Keyed by
    /// `(generation, blob)` rather than by file, because the rows are
    /// content-addressed and two byte-identical files share them; the
    /// generation component retires the whole cache when extraction semantics
    /// move. Bounded by a byte budget, never by workspace size.
    rust_usage_facts: Cache<RustFactCacheKey, Arc<RustUsageFacts>>,
    /// One file's declaration identities and their visibility domains. Keyed by
    /// file rather than by blob because the derivation consults analyzer state
    /// (structural parents, visibility) and not only the file's bytes; the
    /// analyzer is replaced wholesale on `update`, so the cache retires with it.
    declaration_facts: Cache<ProjectFile, Arc<RustDeclarationFacts>>,
    /// The fact catch-up state for this generation: whether the live blobs
    /// without persisted Rust facts have been found and repaired.
    fact_catch_up: Arc<fact_catch_up::RustFactCatchUp>,
    /// The cross-file usage walks' bounded memos. Behind one `Arc` so the
    /// analyzer stays small: nine `Cache` handles inline would make this struct
    /// the outsized variant of `AnalyzerDelegate`.
    walk_caches: Arc<RustWalkCaches>,
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
        token: QueryToken<'_>,
        file: &ProjectFile,
    ) -> Option<Arc<crate::analyzer::tree_sitter_analyzer::PreparedSyntaxTree>> {
        self.inner.prepared_syntax(token, file)
    }

    pub(super) fn analyzer_store(&self) -> &Arc<crate::analyzer::store::AnalyzerStore> {
        self.inner.analyzer_store()
    }

    pub(super) fn live_path_snapshot(&self) -> Arc<crate::analyzer::store::liveness::LiveSnapshot> {
        self.inner.live_path_snapshot()
    }

    /// One blob's persisted per-file usage facts, read once per
    /// `(generation, blob)` and then served from the bounded cache.
    fn rust_usage_facts_of_blob(&self, oid: git2::Oid) -> Option<Arc<RustUsageFacts>> {
        let key: RustFactCacheKey = (self.inner.language_generation("rust"), oid);
        if let Some(cached) = self.rust_usage_facts.get(&key) {
            return Some(cached);
        }
        let facts = self.analyzer_store().rust_usage_facts(oid, "rust").ok()?;
        if facts.modules.is_empty() {
            return None;
        }
        let facts = Arc::new(facts);
        self.rust_usage_facts.insert(key, Arc::clone(&facts));
        Some(facts)
    }

    /// One file's declaration identities and their visibility domains, derived
    /// once per file and then served from the bounded cache.
    fn rust_declaration_facts_of(&self, file: &ProjectFile) -> Arc<RustDeclarationFacts> {
        if let Some(cached) = self.declaration_facts.get(file) {
            return cached;
        }
        let facts = Arc::new(
            brokk_bifrost_rust::usage_queries::rust_declaration_facts(
                self,
                AnalyzerQueryScope::new(self).token(),
                file,
                &self.declarations(file),
                &|| true,
            )
            .expect("uninterrupted Rust declaration-fact derivation"),
        );
        self.declaration_facts
            .insert(file.clone(), Arc::clone(&facts));
        facts
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

    pub(crate) fn signatures_limited(
        &self,
        code_unit: &CodeUnit,
        limit: usize,
    ) -> LimitedQueryRows<String> {
        self.inner.signatures_limited(code_unit, limit)
    }

    #[doc(hidden)]
    pub fn reset_full_hydration_count_for_test(&self) {
        self.inner.reset_full_hydration_count_for_test();
    }

    #[doc(hidden)]
    pub fn full_hydration_count_for_test(&self) -> usize {
        self.inner.full_hydration_count_for_test()
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

    pub(super) fn note_export_name_canonicalization(&self) {
        self.export_name_canonicalization_count
            .fetch_add(1, Ordering::Relaxed);
    }

    #[doc(hidden)]
    pub fn reset_export_name_canonicalization_count_for_test(&self) {
        self.export_name_canonicalization_count
            .store(0, Ordering::Relaxed);
    }

    #[doc(hidden)]
    pub fn export_name_canonicalization_count_for_test(&self) -> usize {
        self.export_name_canonicalization_count
            .load(Ordering::Relaxed)
    }

    pub(crate) fn note_scanned_candidate_file(&self) {
        self.scanned_candidate_file_count
            .fetch_add(1, Ordering::Relaxed);
    }

    #[doc(hidden)]
    pub fn reset_scanned_candidate_file_count_for_test(&self) {
        self.scanned_candidate_file_count
            .store(0, Ordering::Relaxed);
    }

    #[doc(hidden)]
    pub fn scanned_candidate_file_count_for_test(&self) -> usize {
        self.scanned_candidate_file_count.load(Ordering::Relaxed)
    }

    pub(crate) fn note_usage_binding_seed_preparation(&self) {
        self.usage_binding_seed_preparation_count
            .fetch_add(1, Ordering::Relaxed);
    }

    #[doc(hidden)]
    pub fn reset_usage_binding_seed_preparation_count_for_test(&self) {
        self.usage_binding_seed_preparation_count
            .store(0, Ordering::Relaxed);
    }

    #[doc(hidden)]
    pub fn usage_binding_seed_preparation_count_for_test(&self) -> usize {
        self.usage_binding_seed_preparation_count
            .load(Ordering::Relaxed)
    }

    #[doc(hidden)]
    pub fn reset_analyzed_file_listing_count_for_test(&self) {
        self.inner.reset_analyzed_file_listing_count_for_test();
    }

    #[doc(hidden)]
    pub fn analyzed_file_listing_count_for_test(&self) -> usize {
        self.inner.analyzed_file_listing_count_for_test()
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
        self.cargo_routes
            .get_or_build(|| self.build_cargo_routes(), || self.build_cargo_routes())
    }

    /// [`Self::cargo_routes`], abandoning the build once `keep_going` stops
    /// permitting it. A stopped build is not published, so the cell stays empty
    /// for the next complete build.
    fn cargo_routes_while(
        &self,
        keep_going: &(dyn Fn() -> bool + Sync),
    ) -> Option<Arc<RustCargoRouteIndex>> {
        self.cargo_routes.get_or_build_while(
            &|| keep_going(),
            || self.build_cargo_routes_while(keep_going),
            || self.build_cargo_routes_while(keep_going),
        )
    }

    fn build_cargo_routes(&self) -> RustCargoRouteIndex {
        self.build_cargo_routes_while(&|| true)
            .expect("uninterrupted Rust Cargo-route construction")
    }

    fn build_cargo_routes_while(
        &self,
        keep_going: &(dyn Fn() -> bool + Sync),
    ) -> Option<RustCargoRouteIndex> {
        let _scope = brokk_bifrost_core::profiling::scope("RustAnalyzer::build_cargo_routes");
        let files: Vec<_> = self.get_analyzed_files().into_iter().collect();
        let facts = self.rust_module_route_facts(&files, keep_going)?;
        RustCargoRouteIndex::build_while(&files, &facts, &|| keep_going())
    }

    /// The persisted module-route facts of every analyzed Rust file, in one
    /// batched read (issue #1793).
    ///
    /// This replaced hydrating and parsing every file, which was 34-44 s on the
    /// rustc tree and was charged inside the three-second `scan_usages` budget.
    /// The cost is now one chunked index seek per fact table over the live
    /// blobs, so it grows with rows read rather than with source bytes parsed.
    ///
    /// A live blob with no rows is repaired the only way it can be: by parsing
    /// that file. It is a per-file recovery, never a whole-workspace one --
    /// analysis writes these rows, so the shortfall is normally empty and
    /// `module_route_fact_fallback_count_for_test` pins that.
    fn rust_module_route_facts(
        &self,
        files: &[ProjectFile],
        keep_going: &(dyn Fn() -> bool + Sync),
    ) -> Option<HashMap<ProjectFile, RustModuleRouteFacts>> {
        keep_going().then_some(())?;
        let scope = AnalyzerQueryScope::new(self);
        let snapshot = self.live_path_snapshot();
        let oids: Vec<(ProjectFile, git2::Oid)> = files
            .iter()
            .filter_map(|file| Some((file.clone(), snapshot.oid_for_path(file)?)))
            .collect();
        // A failed read is not a separate error path: every file it did not
        // answer for takes the same per-file recovery a missing row takes, and
        // the fallback counter is where that shows up.
        let stored = self
            .analyzer_store()
            .rust_module_route_facts(
                "rust",
                &oids.iter().map(|(_, oid)| *oid).collect::<Vec<_>>(),
            )
            .unwrap_or_default();
        let mut by_file = HashMap::default();
        let mut missing = Vec::new();
        let mut oid_by_file: HashMap<&ProjectFile, git2::Oid> = HashMap::default();
        for (file, oid) in &oids {
            oid_by_file.insert(file, *oid);
        }
        for file in files {
            keep_going().then_some(())?;
            match oid_by_file.get(file).and_then(|oid| stored.get(oid)) {
                Some(found) => {
                    by_file.insert(file.clone(), found.clone());
                }
                None => missing.push(file.clone()),
            }
        }
        for file in missing {
            keep_going().then_some(())?;
            let Some(prepared) = self.prepared_syntax(scope.token(), &file) else {
                continue;
            };
            self.module_route_fact_fallback_count
                .fetch_add(1, Ordering::Relaxed);
            let root = prepared.tree().root_node();
            let item_macros = brokk_bifrost_rust::declarations::rust_rules_item_macro_definitions(
                root,
                prepared.source(),
            );
            by_file.insert(
                file,
                brokk_bifrost_rust::cargo_routes::extract_rust_module_route_facts(
                    root,
                    prepared.source(),
                    &item_macros,
                ),
            );
        }
        Some(by_file)
    }

    #[cfg(test)]
    pub(crate) fn cargo_routes_ready_for_test(&self) -> bool {
        self.cargo_routes.is_ready()
    }

    #[cfg(test)]
    pub(crate) fn hierarchy_index_built_for_test(&self) -> bool {
        self.hierarchy_index.get().is_some()
    }

    /// Files the Cargo-route build recovered by parsing. The structural claim of
    /// #1793 is that this reads zero on a warm workspace: the index composes
    /// from rows and never from a workspace parse.
    #[doc(hidden)]
    pub fn module_route_fact_fallback_count_for_test(&self) -> usize {
        self.module_route_fact_fallback_count
            .load(Ordering::Relaxed)
    }

    #[doc(hidden)]
    pub fn reset_module_route_fact_fallback_count_for_test(&self) {
        self.module_route_fact_fallback_count
            .store(0, Ordering::Relaxed);
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
            export_indexes: build_weighted_cache(memo_budget / 8, weight_export_index),
            reverse_import_index: Arc::new(PoolSafeMemo::new()),
            cargo_routes: Arc::new(PoolSafeMemo::new()),
            package_file_index: Arc::new(OnceLock::new()),
            module_file_resolution_count: Arc::new(AtomicUsize::new(0)),
            export_name_canonicalization_count: Arc::new(AtomicUsize::new(0)),
            scanned_candidate_file_count: Arc::new(AtomicUsize::new(0)),
            usage_binding_seed_preparation_count: Arc::new(AtomicUsize::new(0)),
            module_route_fact_fallback_count: Arc::new(AtomicUsize::new(0)),
            rust_usage_facts: build_weighted_cache(memo_budget / 8, weight_rust_usage_facts),
            declaration_facts: build_weighted_cache(memo_budget / 8, weight_declaration_facts),
            fact_catch_up: Arc::new(fact_catch_up::RustFactCatchUp::new()),
            walk_caches: Arc::new(RustWalkCaches::new(memo_budget)),
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
            export_indexes: build_weighted_cache(memo_budget / 8, weight_export_index),
            reverse_import_index: Arc::new(PoolSafeMemo::new()),
            cargo_routes: Arc::new(PoolSafeMemo::new()),
            package_file_index: Arc::new(OnceLock::new()),
            module_file_resolution_count: Arc::new(AtomicUsize::new(0)),
            export_name_canonicalization_count: Arc::new(AtomicUsize::new(0)),
            scanned_candidate_file_count: Arc::new(AtomicUsize::new(0)),
            usage_binding_seed_preparation_count: Arc::new(AtomicUsize::new(0)),
            module_route_fact_fallback_count: Arc::new(AtomicUsize::new(0)),
            rust_usage_facts: build_weighted_cache(memo_budget / 8, weight_rust_usage_facts),
            declaration_facts: build_weighted_cache(memo_budget / 8, weight_declaration_facts),
            fact_catch_up: Arc::new(fact_catch_up::RustFactCatchUp::new()),
            walk_caches: Arc::new(RustWalkCaches::new(memo_budget)),
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
        rust_type_identifiers(source)
    }
}

/// Whether every changed file the Rust analyzer would reindex still hashes to
/// what the store holds, so `update` can hand back a clone instead of
/// rebuilding.
fn rust_indexed_sources_unchanged(
    index: &dyn CodeUnitIndex,
    changed_files: &BTreeSet<ProjectFile>,
) -> bool {
    changed_files
        .iter()
        .filter(|file| file_language(file) == Language::Rust || index.is_analyzed(file))
        .all(|file| {
            index
                .project()
                .read_source(file)
                .ok()
                .is_some_and(|source| index.indexed_source_matches(file, &source))
        })
}

impl TypeAliasProvider for RustAnalyzer {
    fn is_type_alias(&self, code_unit: &CodeUnit) -> bool {
        self.inner.is_type_alias(code_unit)
    }
}

/// The analyzer owns the retained bounded indexes, so it is the only implementor
/// of the source traits the Rust language logic is written against. Reference
/// contexts themselves are query-scoped views over these indexes.
/// Every method here forwards to an inherent accessor; inherent methods win
/// name resolution, so these bodies do not recurse.
impl brokk_bifrost_rust::graph_support::RustSource for RustAnalyzer {
    fn code_units(&self) -> &dyn CodeUnitIndex {
        self
    }

    fn structural_parent_of(&self, code_unit: &CodeUnit) -> Option<CodeUnit> {
        self.structural_parent_of(code_unit)
    }

    fn prepared_syntax(
        &self,
        token: QueryToken<'_>,
        file: &ProjectFile,
    ) -> Option<Arc<crate::analyzer::tree_sitter_analyzer::PreparedSyntaxTree>> {
        self.prepared_syntax(token, file)
    }

    fn cargo_routes(&self) -> Arc<RustCargoRouteIndex> {
        self.cargo_routes()
    }

    fn cargo_routes_while(
        &self,
        keep_going: &(dyn Fn() -> bool + Sync),
    ) -> Option<Arc<RustCargoRouteIndex>> {
        self.cargo_routes_while(keep_going)
    }

    fn package_file_index(&self) -> Arc<RustPackageFileIndex> {
        self.package_file_index()
    }

    fn import_binder_of(&self, file: &ProjectFile) -> crate::analyzer::usages::ImportBinder {
        self.import_binder_of(file)
    }

    fn export_index_of(&self, file: &ProjectFile) -> Arc<crate::analyzer::usages::ExportIndex> {
        self.export_index_of(file)
    }

    fn note_module_file_resolution(&self) {
        self.note_module_file_resolution();
    }

    fn note_export_name_canonicalization(&self) {
        self.note_export_name_canonicalization();
    }
}

/// The live file-to-blob mapping, handed to `brokk-bifrost-rust` as an
/// object-safe view because `LiveSnapshot` is an analysis-side type.
struct LiveSnapshotBlobs(Arc<crate::analyzer::store::liveness::LiveSnapshot>);

impl RustLiveBlobs for LiveSnapshotBlobs {
    fn oid_for_path(&self, file: &ProjectFile) -> Option<git2::Oid> {
        self.0.oid_for_path(file)
    }

    fn paths_for_oid(&self, oid: git2::Oid) -> Vec<ProjectFile> {
        self.0.paths_for_oid(oid).to_vec()
    }
}

/// The store-backed half of the Rust usage substrate. Everything here is
/// something only the analyzer can answer: the store handle behind the four
/// inverted lookups, the live blob mapping, the caches it owns, and the
/// catch-up that guarantees the rows exist before a walk reads them.
impl RustFactSource for RustAnalyzer {
    fn rust_usage_facts_of_blob(&self, oid: git2::Oid) -> Option<Arc<RustUsageFacts>> {
        self.rust_usage_facts_of_blob(oid)
    }

    fn rust_import_target_blobs(&self, module_path: &str) -> Vec<git2::Oid> {
        self.analyzer_store()
            .rust_import_target_blobs("rust", module_path)
            .unwrap_or_default()
    }

    fn rust_export_blobs(&self, exported_name: &str) -> Vec<git2::Oid> {
        self.analyzer_store()
            .rust_export_blobs("rust", exported_name)
            .unwrap_or_default()
    }

    fn rust_identifier_occurrence_blobs(&self, identifier: &str) -> Vec<(git2::Oid, u32)> {
        self.analyzer_store()
            .rust_identifier_occurrence_blobs("rust", identifier)
            .unwrap_or_default()
    }

    fn rust_include_blobs(&self, file_name: &str) -> Vec<git2::Oid> {
        self.analyzer_store()
            .rust_include_blobs("rust", file_name)
            .unwrap_or_default()
    }

    fn rust_include_host_blobs(&self) -> Vec<git2::Oid> {
        self.analyzer_store()
            .rust_include_host_blobs("rust")
            .unwrap_or_default()
    }

    fn rust_declaration_facts_of(&self, file: &ProjectFile) -> Arc<RustDeclarationFacts> {
        self.rust_declaration_facts_of(file)
    }

    fn live_blobs(&self) -> Arc<dyn RustLiveBlobs> {
        Arc::new(LiveSnapshotBlobs(self.live_path_snapshot()))
    }

    fn walk_caches(&self) -> &Arc<RustWalkCaches> {
        &self.walk_caches
    }

    fn ensure_rust_facts_caught_up(&self) {
        self.ensure_rust_facts_caught_up();
    }

    fn reference_context_of<'a>(
        &'a self,
        token: QueryToken<'a>,
        file: &ProjectFile,
    ) -> RustReferenceContext<'a> {
        self.reference_context_of(token, file)
    }

    fn reference_context_of_with_progress<'a>(
        &'a self,
        token: QueryToken<'a>,
        file: &ProjectFile,
        progress: &'a dyn Fn() -> bool,
    ) -> Option<RustReferenceContext<'a>> {
        progress().then(|| self.reference_context_of_while(token, file, progress))
    }

    fn forward_reference_context_of<'a>(
        &'a self,
        token: QueryToken<'a>,
        file: &ProjectFile,
    ) -> RustReferenceContext<'a> {
        self.forward_reference_context_of(token, file)
    }

    fn forward_reference_context_of_with_progress<'a>(
        &'a self,
        token: QueryToken<'a>,
        file: &ProjectFile,
        progress: &'a dyn Fn() -> bool,
    ) -> Option<RustReferenceContext<'a>> {
        progress().then(|| self.forward_reference_context_of_while(token, file, progress))
    }
}

impl TestDetectionProvider for RustAnalyzer {}

use crate::analyzer::CodeUnitIndex;

impl CodeUnitIndex for RustAnalyzer {
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

    fn retain_analyzed(&self, candidates: &[ProjectFile]) -> Vec<ProjectFile> {
        self.inner.retain_analyzed(candidates)
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

    /// The same owner lookup as the [`CodeUnitIndex::parent_of`] default plus Rust's
    /// structural fallback, routed through the request-scoped owner memo so a
    /// file of N declarations asking for the same owner name costs one store
    /// query rather than N (#1230 item 6).
    fn parent_of(&self, code_unit: &CodeUnit) -> Option<CodeUnit> {
        self.inner
            .definition_parent_unit(code_unit)
            .or_else(|| self.inner.structural_parent_of(code_unit))
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

    fn search_definitions_by_suffix_pattern(
        &self,
        pattern: &str,
        terminal_identifiers: &[String],
        language: Language,
    ) -> BTreeSet<CodeUnit> {
        self.inner
            .search_definitions_by_suffix_pattern(pattern, terminal_identifiers, language)
    }

    fn lookup_candidates_by_short_name(&self, symbol: &str) -> BTreeSet<CodeUnit> {
        self.inner.lookup_candidates_by_short_name(symbol)
    }

    fn has_complete_symbol_lookup_index(&self) -> bool {
        self.inner.has_complete_symbol_lookup_index()
    }

    fn lookup_candidates_by_identifier(&self, identifier: &str) -> BTreeSet<CodeUnit> {
        self.inner.lookup_declarations_by_identifier(identifier)
    }
}

impl IAnalyzer for RustAnalyzer {
    #[cfg(any(test, feature = "test-support"))]
    fn test_hooks(&self) -> &dyn crate::analyzer::AnalyzerTestHooks {
        self
    }

    fn invalidate_cached_file_identities(&self) {
        self.inner.invalidate_cached_file_identities();
    }

    fn working_tree_identity(&self) -> Option<std::sync::Arc<crate::gitblob::WorkingTreeIdentity>> {
        self.inner.working_tree_identity()
    }

    fn abstract_member_implementations(&self, code_unit: &CodeUnit) -> Option<Vec<CodeUnit>> {
        self.rust_trait_member_implementations(code_unit)
    }

    fn begin_query(&self, context: &Arc<crate::analyzer::AnalyzerQueryContext>) {
        self.inner.begin_query(context);
    }

    fn end_query(&self, context: &Arc<crate::analyzer::AnalyzerQueryContext>) {
        self.inner.end_query(context);
    }

    fn record_query_failure(&self, error: crate::analyzer::store::StoreError) {
        self.inner.record_query_failure(error);
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

    /// The hierarchy index still takes double-digit seconds to build on a large
    /// workspace; the Rust usage side no longer builds anything, so its warm is
    /// the fact catch-up, which finds nothing to do on a workspace analysis
    /// already persisted. The two run on separate threads because neither may
    /// wait on the other: on a 401k-file workspace the hierarchy build had not
    /// returned sixteen minutes in (#1757), and a usage query must not inherit
    /// that wait.
    fn warm_query_indexes(&self) {
        std::thread::scope(|scope| {
            scope.spawn(|| self.warm_usage_facts());
            self.hierarchy_index();
        });
    }

    fn query_indexes_warm(&self) -> bool {
        self.hierarchy_index.get().is_some() && self.rust_usage_facts_warm()
    }

    fn update(&self, changed_files: &BTreeSet<ProjectFile>) -> Self {
        if rust_indexed_sources_unchanged(self, changed_files) {
            return self.clone();
        }

        Self {
            inner: self.inner.update(changed_files),
            memo_budget: self.memo_budget,
            imported_code_units: build_weighted_cache(self.memo_budget / 4, weight_code_unit_set),
            referencing_files: build_weighted_cache(self.memo_budget / 8, weight_project_file_set),
            export_indexes: build_weighted_cache(self.memo_budget / 8, weight_export_index),
            reverse_import_index: Arc::new(PoolSafeMemo::new()),
            cargo_routes: Arc::new(PoolSafeMemo::new()),
            package_file_index: Arc::new(OnceLock::new()),
            module_file_resolution_count: Arc::new(AtomicUsize::new(0)),
            export_name_canonicalization_count: Arc::new(AtomicUsize::new(0)),
            scanned_candidate_file_count: Arc::new(AtomicUsize::new(0)),
            usage_binding_seed_preparation_count: Arc::new(AtomicUsize::new(0)),
            module_route_fact_fallback_count: Arc::new(AtomicUsize::new(0)),
            rust_usage_facts: build_weighted_cache(self.memo_budget / 8, weight_rust_usage_facts),
            declaration_facts: build_weighted_cache(self.memo_budget / 8, weight_declaration_facts),
            fact_catch_up: Arc::new(fact_catch_up::RustFactCatchUp::new()),
            walk_caches: Arc::new(RustWalkCaches::new(self.memo_budget)),
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
            export_indexes: build_weighted_cache(self.memo_budget / 8, weight_export_index),
            reverse_import_index: Arc::new(PoolSafeMemo::new()),
            cargo_routes: Arc::new(PoolSafeMemo::new()),
            package_file_index: Arc::new(OnceLock::new()),
            module_file_resolution_count: Arc::new(AtomicUsize::new(0)),
            export_name_canonicalization_count: Arc::new(AtomicUsize::new(0)),
            scanned_candidate_file_count: Arc::new(AtomicUsize::new(0)),
            usage_binding_seed_preparation_count: Arc::new(AtomicUsize::new(0)),
            module_route_fact_fallback_count: Arc::new(AtomicUsize::new(0)),
            rust_usage_facts: build_weighted_cache(self.memo_budget / 8, weight_rust_usage_facts),
            declaration_facts: build_weighted_cache(self.memo_budget / 8, weight_declaration_facts),
            fact_catch_up: Arc::new(fact_catch_up::RustFactCatchUp::new()),
            walk_caches: Arc::new(RustWalkCaches::new(self.memo_budget)),
            hierarchy_index: Arc::new(OnceLock::new()),
            type_relations: Arc::new(OnceLock::new()),
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
        diagnostics::collect_rust_semantic_diagnostics(self, file, source)
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

#[cfg(any(test, feature = "test-support"))]
impl crate::analyzer::AnalyzerTestHooks for RustAnalyzer {
    fn reset_definition_prefetch_batch_count_for_test(&self) {
        self.inner
            .test_hooks()
            .reset_definition_prefetch_batch_count_for_test();
    }

    fn definition_prefetch_batch_count_for_test(&self) -> usize {
        self.inner
            .test_hooks()
            .definition_prefetch_batch_count_for_test()
    }

    fn reset_definition_candidate_row_read_count_for_test(&self) {
        self.inner
            .test_hooks()
            .reset_definition_candidate_row_read_count_for_test();
    }

    fn definition_candidate_row_read_count_for_test(&self) -> usize {
        self.inner
            .test_hooks()
            .definition_candidate_row_read_count_for_test()
    }

    fn reset_definition_candidates_query_count_for_test(&self) {
        self.inner
            .test_hooks()
            .reset_definition_candidates_query_count_for_test();
    }

    fn definition_candidates_query_count_for_test(&self) -> usize {
        self.inner
            .test_hooks()
            .definition_candidates_query_count_for_test()
    }

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

    fn reset_search_candidate_hydration_count_for_test(&self) {
        self.inner
            .test_hooks()
            .reset_search_candidate_hydration_count_for_test();
    }

    fn search_candidate_hydration_count_for_test(&self) -> usize {
        self.inner
            .test_hooks()
            .search_candidate_hydration_count_for_test()
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
}

static RUST_USAGE_STRATEGY: RustExportUsageGraphStrategy = RustExportUsageGraphStrategy::new();

pub(crate) struct RustSupport;

impl LanguageSupport for RustSupport {
    fn language(&self) -> Language {
        Language::Rust
    }

    fn focus_resolves_lexically(&self, focus: tree_sitter::Node<'_>) -> bool {
        matches!(
            brokk_bifrost_rust::field_roles::classify_rust_field_name(focus),
            brokk_bifrost_rust::field_roles::RustFieldNameRole::Other
        )
    }

    fn signature_metadata_limited(
        &self,
        analyzer: &dyn IAnalyzer,
        unit: &CodeUnit,
        limit: usize,
    ) -> Option<LimitedQueryRows<SignatureMetadata>> {
        resolve_analyzer::<RustAnalyzer>(analyzer)
            .map(|rust| rust.signature_metadata_limited(unit, limit))
    }

    fn signatures_limited(
        &self,
        analyzer: &dyn IAnalyzer,
        unit: &CodeUnit,
        limit: usize,
    ) -> Option<LimitedQueryRows<String>> {
        resolve_analyzer::<RustAnalyzer>(analyzer).map(|rust| rust.signatures_limited(unit, limit))
    }

    fn declaration_ranges_limited(
        &self,
        analyzer: &dyn IAnalyzer,
        unit: &CodeUnit,
        limit: usize,
    ) -> Option<LimitedQueryRows<Range>> {
        resolve_analyzer::<RustAnalyzer>(analyzer).map(|rust| rust.ranges_limited(unit, limit))
    }

    fn forward_query_provider<'a>(
        &self,
        analyzer: &'a dyn IAnalyzer,
    ) -> Option<&'a dyn ForwardQueryProvider> {
        resolve_analyzer::<RustAnalyzer>(analyzer).map(|value| value as _)
    }

    fn ecosystem(&self) -> UsageEcosystem {
        UsageEcosystem::Rust
    }

    fn usage_strategy(&self) -> &'static dyn GraphUsageAnalyzer {
        &RUST_USAGE_STRATEGY
    }

    fn edge_pass(&self) -> Option<&'static dyn LanguageEdgePass> {
        Some(&RustEdgePass)
    }

    fn dead_code(&self) -> DeadCodeSupport {
        DeadCodeSupport {
            strategy: Some(&RUST_USAGE_STRATEGY),
            bulk: Some(&RustDeadCodeBulk),
        }
    }

    fn structural_receiver(&self) -> Option<&'static dyn StructuralReceiverResolver> {
        Some(&RustSupport)
    }

    /// Pre-build persisted Rust usage facts and the Cargo route index.
    /// These are otherwise charged to whichever request first touches the Rust
    /// usage graph, which can push a single interactive `scan_usages` call
    /// past its wall-clock budget on a large workspace (issue #1416). A no-op
    /// for workspaces without Rust.
    fn warm_usage_analysis(&self, analyzer: &dyn IAnalyzer) {
        let Some(rust) = resolve_analyzer::<RustAnalyzer>(analyzer) else {
            return;
        };
        // The build issues per-file store queries that are only cheap under
        // request-scoped memoization; without a scope each lookup re-hydrates
        // (observed ~65s instead of ~3.5s on the Bifrost workspace).
        let _scope = crate::analyzer::AnalyzerQueryScope::new(analyzer);
        rust.warm_usage_facts();
    }

    fn parser_language(&self, _flavor: crate::analyzer::ParserFlavor) -> tree_sitter::Language {
        tree_sitter_rust::LANGUAGE.into()
    }

    fn structural_spec(&self) -> &'static dyn crate::analyzer::structural::StructuralSpec {
        &brokk_bifrost_rust::structural::RUST_STRUCTURAL_SPEC
    }

    fn highlight_query(&self) -> Option<&'static str> {
        Some(tree_sitter_rust::HIGHLIGHTS_QUERY)
    }
}

struct RustEdgePass;

impl LanguageEdgePass for RustEdgePass {
    fn id(&self) -> EdgePassId {
        EdgePassId::Rust
    }

    fn edge_sites(&self, ctx: &EdgeSiteScanCtx<'_>) -> Option<LanguageEdgeSites> {
        build_rust_usage_edges(ctx.analyzer, ctx.fqns, ctx.keep_file).map(LanguageEdgeSites)
    }

    fn edge_weights(&self, ctx: &EdgeWeightScanCtx<'_>) -> Option<LanguageEdgeWeights> {
        build_rust_usage_edge_weights(ctx.analyzer, ctx.fqns, ctx.keep_file)
            .map(LanguageEdgeWeights::Fqn)
    }
}

impl StructuralReceiverResolver for RustSupport {
    fn resolve_type_bounded(
        &self,
        query: BoundedReceiverQuery<'_>,
    ) -> BoundedResolution<TypeLookupOutcome> {
        resolve_rust_type_bounded(
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
        let scope = AnalyzerQueryScope::new(query.analyzer);
        resolve_rust_bounded(
            query.analyzer,
            scope.token(),
            query.file,
            query.source,
            query.tree,
            query.site,
            query.budget,
            query.cancellation,
        )
    }
}

struct RustDeadCodeBulk;

impl DeadCodeBulkProof for RustDeadCodeBulk {
    fn id(&self) -> EdgePassId {
        EdgePassId::Rust
    }

    /// Inherent and trait members are held back: the bulk pass keys by fq name, which
    /// cannot separate two `impl` blocks' identically named members.
    fn needs_precise_scan(&self, routing: DeadCodeRouting<'_>) -> bool {
        let DeadCodeRouting {
            analyzer,
            candidate,
            ..
        } = routing;
        if !(candidate.is_function() || candidate.is_field()) {
            return false;
        }
        let Some(rust) = resolve_analyzer::<RustAnalyzer>(analyzer) else {
            return false;
        };
        rust.parent_of(candidate).is_some()
    }

    /// The only proof with a standalone analyzer-availability check, and the only one
    /// whose file cap is measured off the analyzer's own analyzed-file list rather than
    /// the project's analyzable set for the language.
    fn preflight(&self, analyzer: &dyn IAnalyzer) -> DeadCodeBulkPreflight {
        let Some(rust) = resolve_analyzer::<RustAnalyzer>(analyzer) else {
            return DeadCodeBulkPreflight::Unavailable("Rust analyzer capability was unavailable");
        };
        DeadCodeBulkPreflight::Ready {
            label: "Rust",
            files: rust.get_analyzed_files().len(),
        }
    }

    fn build(
        &self,
        analyzer: &dyn IAnalyzer,
        candidates: &[CodeUnit],
    ) -> Option<DeadCodeBulkEdges> {
        let nodes = fqn_bulk_nodes(
            analyzer,
            Language::Rust,
            |unit| unit.is_function() || unit.is_class(),
            candidates,
        );
        build_rust_usage_edges(analyzer, &nodes, |_| true)
            .map(|edges| DeadCodeBulkEdges::Fqn(Arc::new(edges)))
    }
}
