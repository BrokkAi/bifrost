mod adapter;
mod cache;
mod call_conversion;
mod cargo_routes;
mod clones;
pub(crate) mod crate_identity;
mod dependency_discovery;
pub(crate) mod diagnostics;
mod external;
mod fact_catch_up;
pub(crate) mod generated_model;
mod graph_support;
mod hierarchy;
mod imports;
pub(crate) mod native_call_projection;
mod native_graph;
#[cfg(test)]
pub(crate) use native_graph::{
    RustNativeWorkspaceGraphOutcome, build_rust_native_workspace_graph_for_files,
};
pub(crate) mod external_calls;
mod native_outgoing;
pub(crate) mod native_points;
mod native_rename;
mod native_usages;
pub use native_usages::RustNativeUsageStrategy;
mod rustdoc_artifact;
pub(crate) mod selected_projection;
pub(crate) mod selected_reverse;
pub(crate) mod selected_shadow;
mod semantic;
pub(in crate::analyzer) mod source_publication;
pub(crate) mod source_storage;
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
    BoundedReceiverQuery, DeadCodeSupport, ExternalCalleeSite, ImportedExternalCallee,
    LanguageSupport, StructuralReceiverResolver,
};
use crate::analyzer::semantic::ResolverOwnedExternalCalleeIdentity;
use crate::analyzer::store::LimitedQueryRows;
use crate::analyzer::usages::get_definition::{
    BoundedResolution, DefinitionLookupOutcome, ExactExternalCallProof,
};
use crate::analyzer::usages::get_type::TypeLookupOutcome;
use crate::analyzer::usages::workspace_graph::UsageEcosystem;
use crate::analyzer::{
    AnalyzerConfig, AnalyzerStoreContext, BuildProgress, CloneSmell, CloneSmellWeights, CodeUnit,
    ForwardQueryProvider, IAnalyzer, ImportAnalysisProvider, Language, PoolSafeMemo, Project,
    ProjectFile, Range, SignatureMetadata, StructuredImportPath, TestAssertionSmell,
    TestAssertionWeights, TestDetectionProvider, TreeSitterAnalyzer, TypeAliasProvider,
    TypeHierarchyProvider, resolve_analyzer,
};
use crate::analyzer::{AnalyzerQueryScope, QueryScope};
use crate::hash::{HashMap, HashSet};
use external_calls::{rust_call_written_arity, rust_import_binder_external_callee};
use moka::sync::Cache;
use std::collections::BTreeSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};

use super::weighted_cache::{build_weighted_cache, weight_code_unit_set, weight_project_file_set};
pub(crate) use adapter::RustAdapter;
use brokk_bifrost_core::analyzer::rust_facts::{RustModuleRouteFacts, RustUsageFacts};
use brokk_bifrost_rust::cache::{
    weight_declaration_facts, weight_declaration_source_properties, weight_rust_usage_facts,
};
use brokk_bifrost_rust::graph_support::{
    RustCargoRouteError, RustDeclarationSourceProperties, RustFactSource, RustLiveBlobs,
    RustPlacedDeclaration, RustTraitImplRow, RustUnresolvedImpl,
};
use brokk_bifrost_rust::hierarchy::RustHierarchySourceFacts;
use brokk_bifrost_rust::usage_queries::RustDeclarationFacts;
use brokk_bifrost_rust::usage_walks::RustWalkCaches;

/// The key of the per-blob fact cache: the rows are content-addressed, and the
/// generation component retires the whole cache when extraction semantics move.
type RustFactCacheKey = (Option<crate::analyzer::store::GenerationId>, git2::Oid);
type RustHierarchySourceFactsCacheKey =
    (crate::analyzer::store::GenerationId, git2::Oid, ProjectFile);

/// Query occurrences and their immutable fact product share one selected blob.
#[cfg(test)]
pub(crate) struct RustPrimarySourceAt {
    pub(crate) occurrences: Vec<brokk_bifrost_core::analyzer::source_facts::SourceOccurrenceId>,
    pub(crate) facts: Arc<RustHierarchySourceFacts>,
}

fn weight_rust_hierarchy_source_facts<K>(_key: &K, value: &Arc<RustHierarchySourceFacts>) -> u32 {
    value.estimated_retained_bytes().clamp(1, u32::MAX as usize) as u32
}
use brokk_bifrost_rust::cargo_routes::RustCargoRouteIndex;
use brokk_bifrost_rust::crate_naming;
#[cfg(test)]
pub(crate) use brokk_bifrost_rust::declarations::rust_package_name;
pub(crate) use brokk_bifrost_rust::declarations::rust_type_identifiers;
pub use brokk_bifrost_rust::field_roles::rust_is_field_declaration_name;
pub use brokk_bifrost_rust::graph_support::rust_reference_namespace;
pub(crate) use brokk_bifrost_rust::imports::rust_import_binding_name;
use brokk_bifrost_rust::test_detection::detect_rust_test_assertion_smells;
use cache::weight_export_index;
use clones::build_rust_clone_candidate_data;
pub use dependency_discovery::resolve_rust_semantic_pack_dependencies;
pub use external::RustDependencyPackAdapter;
pub use rustdoc_artifact::RustdocJsonPackProducer;

pub use brokk_bifrost_rust::graph_support::RustReferenceContext;
use brokk_bifrost_rust::graph_support::is_rust_enum_variant_declaration;
pub(crate) use brokk_bifrost_rust::graph_support::is_rust_public_like_declaration;
use brokk_bifrost_rust::graph_support::{
    ReferenceContextError, ReferenceContextResult, RustPackageFileIndex,
};
#[cfg(any(test, feature = "test-support"))]
pub use brokk_bifrost_rust::lexical_scope::{
    reset_rust_tree_parse_counters_for_test, rust_scope_index_build_count_for_test,
    rust_tree_parse_count_for_test, rust_tree_parse_request_count_for_test,
    rust_tree_parsed_bytes_for_test,
};
pub use brokk_bifrost_rust::usage::RustReferenceNamespace;
use brokk_bifrost_rust::usage::RustSymbolNamespace;

pub fn rust_declaration_matches_reference_namespace(
    declaration: &CodeUnit,
    reference: RustReferenceNamespace,
) -> bool {
    RustSymbolNamespace::of(declaration)
        .is_some_and(|symbol_namespace| symbol_namespace.accepts(reference))
}

pub fn rust_declaration_is_enum_variant(
    rust: &RustAnalyzer,
    declaration: &CodeUnit,
) -> Result<bool, RustCargoRouteError> {
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
    // The current builder reads persisted rows and composes routes serially.
    // PoolSafeMemo's pool-independent path lets Rayon callers share that work
    // with cancellable waits, without duplicating the build on each worker.
    cargo_routes: Arc<PoolSafeMemo<RustCargoRouteIndex>>,
    package_file_index: Arc<OnceLock<Arc<RustPackageFileIndex>>>,
    /// `resolve_module_files` calls. A use-path's module files are invariant in
    /// the export name being resolved, so this count is what proves the
    /// per-export-name recomputation is gone (#1230 item 4).
    module_file_resolution_count: Arc<AtomicUsize>,
    export_name_canonicalization_count: Arc<AtomicUsize>,
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
    declaration_source_properties: Cache<
        (crate::analyzer::store::GenerationId, git2::Oid, ProjectFile),
        Arc<RustDeclarationSourceProperties>,
    >,
    /// One mounted file's canonical hierarchy inputs. The generation, blob,
    /// and mounted file all participate in the key: source rows are
    /// content-owned, while CodeUnit links are placement-dependent.
    rust_hierarchy_source_facts:
        Cache<RustHierarchySourceFactsCacheKey, Arc<RustHierarchySourceFacts>>,
    /// The fact catch-up state for this generation: whether the live blobs
    /// without persisted Rust facts have been found and repaired.
    fact_catch_up: Arc<fact_catch_up::RustFactCatchUp>,
    /// The cross-file usage walks' bounded memos. Behind one `Arc` so the
    /// analyzer stays small: nine `Cache` handles inline would make this struct
    /// the outsized variant of `AnalyzerDelegate`.
    walk_caches: Arc<RustWalkCaches>,
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
    fn rust_usage_facts_of_blob(
        &self,
        oid: git2::Oid,
    ) -> Result<Arc<RustUsageFacts>, RustCargoRouteError> {
        let key: RustFactCacheKey = (self.inner.language_generation("rust"), oid);
        if let Some(cached) = self.rust_usage_facts.get(&key) {
            return Ok(cached);
        }
        let facts = self
            .analyzer_store()
            .rust_usage_facts(oid, "rust")
            .map_err(|error| {
                self.inner.record_store_error(
                    error.context(format!("reading canonical Rust usage facts for blob {oid}")),
                );
                RustCargoRouteError::Unavailable
            })?;
        if !facts
            .modules
            .first()
            .is_some_and(|root| root.module_name.is_empty() && root.is_inline)
        {
            self.inner
                .record_store_error(crate::analyzer::store::StoreError::new(format!(
                    "canonical Rust usage publication has no root module for blob {oid}: {:?}",
                    facts.modules
                )));
            return Err(RustCargoRouteError::Unavailable);
        }
        let facts = Arc::new(facts);
        self.rust_usage_facts.insert(key, Arc::clone(&facts));
        Ok(facts)
    }

    /// One file's declaration identities and their visibility domains, derived
    /// once per file and then served from the bounded cache.
    fn rust_declaration_facts_of(
        &self,
        file: &ProjectFile,
    ) -> Result<Arc<RustDeclarationFacts>, RustCargoRouteError> {
        if let Some(cached) = self.declaration_facts.get(file) {
            return Ok(cached);
        }
        let facts = Arc::new(
            brokk_bifrost_rust::usage_queries::rust_declaration_facts(
                self,
                file,
                &self.declarations(file),
                &|| true,
            )?
            .expect("uninterrupted Rust declaration-fact derivation"),
        );
        self.declaration_facts
            .insert(file.clone(), Arc::clone(&facts));
        Ok(facts)
    }

    fn selected_rust_source(
        &self,
        file: &ProjectFile,
    ) -> Result<(crate::analyzer::store::GenerationId, git2::Oid), RustCargoRouteError> {
        let generation = self
            .inner
            .language_generation("rust")
            .expect("Rust analyzer has a Rust storage generation");
        let Some(oid) = self.live_path_snapshot().oid_for_path(file) else {
            // A file this adapter does not own has no canonical Rust source
            // and never will, so asking about one is not a store failure. It
            // used to record one, and a recorded store error fails the whole
            // request: a mixed-language `usage_graph` naming only Rust paths
            // exited 1 on a C++ header. Only a missing *Rust* source is a
            // store problem.
            if crate::analyzer::common::language_for_file(file) == Language::Rust {
                self.inner
                    .record_store_error(crate::analyzer::store::StoreError::new(format!(
                        "canonical Rust source is absent from the live snapshot: {file:?}"
                    )));
            }
            return Err(RustCargoRouteError::Unavailable);
        };
        Ok((generation, oid))
    }

    fn declaration_source_properties(
        &self,
        file: &ProjectFile,
        keep_going: &dyn Fn() -> bool,
    ) -> Result<Arc<RustDeclarationSourceProperties>, RustCargoRouteError> {
        if !keep_going() {
            return Err(RustCargoRouteError::Cancelled);
        }
        let (generation, oid) = self.selected_rust_source(file)?;
        let key = (generation, oid, file.clone());
        if let Some(cached) = self.declaration_source_properties.get(&key) {
            return Ok(cached);
        }
        let rows = self
            .analyzer_store()
            .rust_declaration_properties(oid, generation, &RustAdapter, file, keep_going)
            .map_err(|error| {
                self.inner.record_store_error(error.context(format!(
                    "reading canonical Rust declaration properties for {file:?} ({oid})"
                )));
                RustCargoRouteError::Unavailable
            })?
            .ok_or(RustCargoRouteError::Cancelled)?;
        let mut properties = RustDeclarationSourceProperties::default();
        for (unit, property) in rows {
            if !keep_going() {
                return Err(RustCargoRouteError::Cancelled);
            }
            properties.entry(unit).or_default().push(property);
        }
        if !keep_going() {
            return Err(RustCargoRouteError::Cancelled);
        }
        let properties = Arc::new(properties);
        self.declaration_source_properties
            .insert(key, Arc::clone(&properties));
        Ok(properties)
    }

    /// One mounted file's complete canonical hierarchy input. Publication is
    /// read from the current generation and failures are never inserted into
    /// the bounded cache; the store's `None` result is cancellation.
    pub(crate) fn canonical_rust_hierarchy_source_facts(
        &self,
        file: &ProjectFile,
        keep_going: &dyn Fn() -> bool,
    ) -> Result<Arc<RustHierarchySourceFacts>, RustCargoRouteError> {
        if !keep_going() {
            return Err(RustCargoRouteError::Cancelled);
        }
        let (generation, oid) = self.selected_rust_source(file)?;
        self.rust_hierarchy_source_facts_for_key((generation, oid, file.clone()), keep_going)
    }

    fn rust_hierarchy_source_facts_for_key(
        &self,
        key: RustHierarchySourceFactsCacheKey,
        keep_going: &dyn Fn() -> bool,
    ) -> Result<Arc<RustHierarchySourceFacts>, RustCargoRouteError> {
        if !keep_going() {
            return Err(RustCargoRouteError::Cancelled);
        }
        let (generation, oid, file) = &key;
        if let Some(cached) = self.rust_hierarchy_source_facts.get(&key) {
            return Ok(cached);
        }
        let facts = self
            .analyzer_store()
            .rust_hierarchy_source_facts(*oid, *generation, &RustAdapter, file, keep_going)
            .map_err(|error| {
                self.inner.record_store_error(error.context(format!(
                    "reading canonical Rust hierarchy source facts for {file:?} ({oid})"
                )));
                RustCargoRouteError::Unavailable
            })?
            .ok_or(RustCargoRouteError::Cancelled)?;
        if !keep_going() {
            return Err(RustCargoRouteError::Cancelled);
        }
        let facts = Arc::new(facts);
        self.rust_hierarchy_source_facts
            .insert(key, Arc::clone(&facts));
        Ok(facts)
    }

    #[cfg(test)]
    pub(crate) fn canonical_rust_primary_source_at(
        &self,
        file: &ProjectFile,
        range: std::ops::Range<usize>,
        keep_going: &dyn Fn() -> bool,
    ) -> Result<RustPrimarySourceAt, RustCargoRouteError> {
        if !keep_going() {
            return Err(RustCargoRouteError::Cancelled);
        }
        let (generation, oid) = self.selected_rust_source(file)?;
        let occurrences = self
            .analyzer_store()
            .rust_primary_occurrences_at(oid, generation, range, keep_going)
            .map_err(|error| {
                self.inner.record_store_error(error.context(format!(
                    "reading canonical Rust primary query occurrences for {file:?} ({oid})"
                )));
                RustCargoRouteError::Unavailable
            })?
            .ok_or(RustCargoRouteError::Cancelled)?;
        // Occurrence IDs are blob-local. Never recapture live identity between
        // point selection and hierarchy loading if a mount changes during I/O.
        let facts =
            self.rust_hierarchy_source_facts_for_key((generation, oid, file.clone()), keep_going)?;
        Ok(RustPrimarySourceAt { occurrences, facts })
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
        clone.imported_code_units =
            build_weighted_cache(self.memo_budget / 4, weight_code_unit_set);
        clone.referencing_files =
            build_weighted_cache(self.memo_budget / 8, weight_project_file_set);
        clone.export_indexes = build_weighted_cache(self.memo_budget / 8, weight_export_index);
        clone.reverse_import_index = Arc::new(PoolSafeMemo::new());
        clone.cargo_routes = Arc::new(PoolSafeMemo::new());
        clone.package_file_index = Arc::new(OnceLock::new());
        clone.declaration_facts =
            build_weighted_cache(self.memo_budget / 8, weight_declaration_facts);
        clone.rust_hierarchy_source_facts =
            build_weighted_cache(self.memo_budget / 16, weight_rust_hierarchy_source_facts);
        clone.fact_catch_up = Arc::new(fact_catch_up::RustFactCatchUp::new());
        clone.walk_caches = Arc::new(RustWalkCaches::new(self.memo_budget));
        clone
    }

    pub(crate) fn clone_for_index_warm(&self, project: Arc<dyn Project>) -> Self {
        let mut clone = self.clone();
        clone.inner = clone.inner.clone_with_project(project);
        clone
    }

    /// Explicit inverse-analysis support. Forward definition and type queries
    /// resolve only the importing file's manifest route.
    fn cargo_routes(&self) -> Result<Arc<RustCargoRouteIndex>, RustCargoRouteError> {
        // Preparation belongs to warm_usage_facts, not a route read. This
        // accessor is also reachable through forward resolution helpers, so
        // repairing the workspace here would bypass their query budgets.
        self.cargo_routes_while(&|| true)
    }

    /// [`Self::cargo_routes`], abandoning the build once `keep_going` stops
    /// permitting it. A stopped build is not published, so the cell stays empty
    /// for the next complete build.
    fn cargo_routes_while(
        &self,
        keep_going: &dyn Fn() -> bool,
    ) -> Result<Arc<RustCargoRouteIndex>, RustCargoRouteError> {
        // This build only reads frozen mounts, SQL, and Cargo manifests; it
        // cannot enter parser preparation or require a rayon worker. Failures
        // and cancelled builds publish nothing to the memo.
        let routes = self
            .cargo_routes
            .get_or_try_build_pool_independent_while(&|| keep_going(), || {
                match self.build_cargo_routes_while(keep_going) {
                    Ok(routes) => Ok(Some(routes)),
                    Err(RustCargoRouteError::Cancelled) => Ok(None),
                    Err(error) => Err(error),
                }
            })?
            .ok_or(RustCargoRouteError::Cancelled)?;
        self.note_rust_publication_verified();
        Ok(routes)
    }

    fn build_cargo_routes_while(
        &self,
        keep_going: &dyn Fn() -> bool,
    ) -> Result<RustCargoRouteIndex, RustCargoRouteError> {
        let _scope = brokk_bifrost_core::profiling::scope("RustAnalyzer::build_cargo_routes");
        if !keep_going() {
            return Err(RustCargoRouteError::Cancelled);
        }
        let mut mounts = self
            .inner
            .live_file_mounts_for_fact_publication_while(&|| keep_going())
            .ok_or(RustCargoRouteError::Cancelled)?;
        mounts.sort_unstable_by(|(left, _), (right, _)| left.cmp(right));
        let facts = self.rust_module_route_facts(&mounts, keep_going)?;
        let files: Vec<_> = mounts.into_iter().map(|(file, _)| file).collect();
        RustCargoRouteIndex::build_while(&files, &facts, &|| keep_going())
            .ok_or(RustCargoRouteError::Cancelled)
    }

    /// The persisted module-route facts of every analyzed Rust file, in one
    /// batched read (issue #1793).
    ///
    /// This replaced hydrating and parsing every file, which was 34-44 s on the
    /// rustc tree and was charged inside the three-second `scan_usages` budget.
    /// The cost is now one chunked index seek per fact table over the live
    /// blobs, so it grows with rows read rather than with source bytes parsed.
    ///
    /// Missing publication is unavailable, never an independent parser path.
    /// Normal preparation or explicit warming can repair it before a retry;
    /// this bounded consumer only composes already-published canonical output.
    fn rust_module_route_facts(
        &self,
        files: &[(ProjectFile, git2::Oid)],
        keep_going: &dyn Fn() -> bool,
    ) -> Result<HashMap<ProjectFile, RustModuleRouteFacts>, RustCargoRouteError> {
        if !keep_going() {
            return Err(RustCargoRouteError::Cancelled);
        }
        let mut missing = Vec::new();
        let generation = self
            .inner
            .language_generation("rust")
            .expect("Rust analyzer has a Rust storage generation");
        let keys: Vec<_> = files.iter().map(|(_, oid)| *oid).collect();
        let stored = self
            .analyzer_store()
            .rust_module_route_facts_while("rust", generation, &keys, &|| keep_going())
            .map_err(|error| {
                self.inner.record_store_error(
                    error.context("reading canonical Rust Cargo-route publication"),
                );
                RustCargoRouteError::Unavailable
            })?
            .ok_or(RustCargoRouteError::Cancelled)?;
        let mut by_file = HashMap::default();
        for (file, oid) in files {
            if !keep_going() {
                return Err(RustCargoRouteError::Cancelled);
            }
            match stored.get(oid) {
                Some(facts) if facts.file_extent().is_some() => {
                    by_file.insert(file.clone(), facts.clone());
                }
                _ => missing.push(file.clone()),
            }
        }
        if !missing.is_empty() {
            self.inner.record_store_error(crate::analyzer::store::StoreError::new(format!(
                "canonical Rust Cargo-route publication is unavailable for live files: {missing:?}"
            )));
            return Err(RustCargoRouteError::Unavailable);
        }
        Ok(by_file)
    }

    #[cfg(test)]
    pub(crate) fn cargo_routes_ready_for_test(&self) -> bool {
        self.cargo_routes.is_ready()
    }

    #[cfg(test)]
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

    pub fn new(project: Arc<dyn Project>) -> Self {
        Self::new_with_config(project, AnalyzerConfig::default())
    }

    pub fn new_with_config(project: Arc<dyn Project>, config: AnalyzerConfig) -> Self {
        crate_naming::invalidate();
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
            module_route_fact_fallback_count: Arc::new(AtomicUsize::new(0)),
            rust_usage_facts: build_weighted_cache(memo_budget / 8, weight_rust_usage_facts),
            declaration_facts: build_weighted_cache(memo_budget / 16, weight_declaration_facts),
            declaration_source_properties: build_weighted_cache(
                memo_budget / 16,
                weight_declaration_source_properties,
            ),
            rust_hierarchy_source_facts: build_weighted_cache(
                memo_budget / 16,
                weight_rust_hierarchy_source_facts,
            ),
            fact_catch_up: Arc::new(fact_catch_up::RustFactCatchUp::new()),
            walk_caches: Arc::new(RustWalkCaches::new(memo_budget)),
        }
    }

    pub(crate) fn new_with_config_store_context(
        project: Arc<dyn Project>,
        config: AnalyzerConfig,
        store_context: AnalyzerStoreContext,
        progress: Option<BuildProgress>,
    ) -> Result<Self, crate::analyzer::store::StoreError> {
        crate_naming::invalidate();
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
            module_route_fact_fallback_count: Arc::new(AtomicUsize::new(0)),
            rust_usage_facts: build_weighted_cache(memo_budget / 8, weight_rust_usage_facts),
            declaration_facts: build_weighted_cache(memo_budget / 16, weight_declaration_facts),
            declaration_source_properties: build_weighted_cache(
                memo_budget / 16,
                weight_declaration_source_properties,
            ),
            rust_hierarchy_source_facts: build_weighted_cache(
                memo_budget / 16,
                weight_rust_hierarchy_source_facts,
            ),
            fact_catch_up: Arc::new(fact_catch_up::RustFactCatchUp::new()),
            walk_caches: Arc::new(RustWalkCaches::new(memo_budget)),
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

/// Whether `file` is a Cargo manifest, the non-source input that names crates
/// and their path dependencies. `Cargo.toml` maps to no language, so the
/// workspace analyzer must route it to the Rust delegate by name.
///
/// It is the only Rust configuration file routed here (decided in #3756):
/// - `Cargo.lock` and `rust-toolchain.toml` are read only by dependency
///   discovery (`dependency_discovery.rs`), to choose the dependency and
///   standard-library packs. They are Cargo pack inputs
///   (`CargoDependencyResolver::dependency_inputs`), and the host refreshes
///   pack activation when one changes. Crate rows, cfg and feature activation,
///   and Cargo routes do not read them, and pack-derived semantic artifacts
///   are keyed by the active packs, so routing them here would rebuild for no
///   change in results.
/// - `.cargo/config.toml` is read by nothing: its `[patch]`, `build.target`
///   and `--cfg` rustflags are not honored (#3768). Route it when they are.
pub(crate) fn is_cargo_manifest(file: &ProjectFile) -> bool {
    file.rel_path()
        .file_name()
        .is_some_and(|name| name == "Cargo.toml")
}

/// Whether every changed file the Rust analyzer would reindex still hashes to
/// what the store holds, so `update` can hand back a clone instead of
/// rebuilding.
///
/// A changed manifest is never "unchanged": it moves crate membership and
/// dependency routes without touching a Rust source, and only the underlying
/// analyzer's update re-derives the crate rows for it.
fn rust_indexed_sources_unchanged(
    index: &dyn CodeUnitIndex,
    changed_files: &BTreeSet<ProjectFile>,
) -> bool {
    if changed_files.iter().any(is_cargo_manifest) {
        return false;
    }
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

    fn declaration_candidates_by_fqn_while(
        &self,
        fq_name: &str,
        keep_going: &dyn Fn() -> bool,
    ) -> ReferenceContextResult<Vec<CodeUnit>> {
        if !keep_going() {
            return Err(ReferenceContextError::Interrupted);
        }
        if !self.inner.workspace_declaration_identities_authoritative() {
            return Err(RustCargoRouteError::Unavailable.into());
        }
        let mut interrupted = false;
        let candidates = self.declaration_candidates_by_fqn_limited(fq_name, usize::MAX, || {
            let proceed = keep_going();
            interrupted |= !proceed;
            proceed
        });
        if interrupted || !keep_going() {
            return Err(ReferenceContextError::Interrupted);
        }
        if !candidates.complete {
            return Err(RustCargoRouteError::Unavailable.into());
        }
        Ok(candidates.rows)
    }

    fn declaration_source_properties(
        &self,
        file: &ProjectFile,
        keep_going: &dyn Fn() -> bool,
    ) -> Result<Arc<RustDeclarationSourceProperties>, RustCargoRouteError> {
        self.declaration_source_properties(file, keep_going)
    }

    fn direct_ancestors(&self, code_unit: &CodeUnit) -> Result<Vec<CodeUnit>, RustCargoRouteError> {
        self.direct_ancestors(code_unit)
    }

    fn prepared_syntax(
        &self,
        token: QueryToken<'_>,
        file: &ProjectFile,
    ) -> Option<Arc<crate::analyzer::tree_sitter_analyzer::PreparedSyntaxTree>> {
        self.prepared_syntax(token, file)
    }

    fn cargo_routes(&self) -> Result<Arc<RustCargoRouteIndex>, RustCargoRouteError> {
        self.cargo_routes()
    }

    fn cargo_routes_while(
        &self,
        keep_going: &dyn Fn() -> bool,
    ) -> Result<Arc<RustCargoRouteIndex>, RustCargoRouteError> {
        self.cargo_routes_while(keep_going)
    }

    fn package_file_index(&self) -> Arc<RustPackageFileIndex> {
        self.package_file_index()
    }

    fn import_binder_of(&self, file: &ProjectFile) -> crate::analyzer::usages::ImportBinder {
        let scope = AnalyzerQueryScope::new(self);
        let token = scope.token();
        self.import_binder_of(token, file)
    }

    fn export_index_of(
        &self,
        file: &ProjectFile,
    ) -> brokk_bifrost_rust::graph_support::ReferenceContextResult<
        Arc<crate::analyzer::usages::ExportIndex>,
    > {
        self.export_index_of(file)
    }

    fn export_index_of_while(
        &self,
        file: &ProjectFile,
        progress: &dyn Fn() -> bool,
    ) -> brokk_bifrost_rust::graph_support::ReferenceContextResult<
        Arc<crate::analyzer::usages::ExportIndex>,
    > {
        self.export_index_of_while(file, progress)
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

fn placed_declarations(rows: Vec<(git2::Oid, u32, String)>) -> Vec<RustPlacedDeclaration> {
    rows.into_iter()
        .map(|(blob, declaration, rel_path)| RustPlacedDeclaration {
            rel_path,
            blob,
            declaration,
        })
        .collect()
}

/// The store-backed half of the Rust usage substrate. Everything here is
/// something only the analyzer can answer: the store handle behind the six
/// inverted lookups, the live blob mapping, and the caches it owns.
/// Publication preparation is deliberately not part of this query interface.
impl RustFactSource for RustAnalyzer {
    fn rust_usage_facts_of_blob(
        &self,
        oid: git2::Oid,
    ) -> Result<Arc<RustUsageFacts>, RustCargoRouteError> {
        self.rust_usage_facts_of_blob(oid)
    }

    fn rust_import_target_blobs(
        &self,
        module_path: &str,
    ) -> Result<Vec<git2::Oid>, RustCargoRouteError> {
        self.analyzer_store()
            .rust_import_target_blobs("rust", module_path)
            .map_err(|error| {
                self.inner.record_store_error(
                    error.context(format!("reading Rust import targets for {module_path:?}")),
                );
                RustCargoRouteError::Unavailable
            })
    }

    fn rust_module_import_candidate_blobs(
        &self,
        component: &str,
    ) -> Result<Vec<git2::Oid>, RustCargoRouteError> {
        self.analyzer_store()
            .rust_module_import_candidate_blobs("rust", component)
            .map_err(|error| {
                self.inner.record_store_error(error.context(format!(
                    "reading Rust module import candidates for {component:?}"
                )));
                RustCargoRouteError::Unavailable
            })
    }

    fn rust_export_blobs(
        &self,
        exported_name: &str,
    ) -> Result<Vec<git2::Oid>, RustCargoRouteError> {
        self.analyzer_store()
            .rust_export_blobs("rust", exported_name)
            .map_err(|error| {
                self.inner.record_store_error(
                    error.context(format!("reading Rust exports for {exported_name:?}")),
                );
                RustCargoRouteError::Unavailable
            })
    }

    fn rust_traits_implemented_by(
        &self,
        declaration: &RustPlacedDeclaration,
    ) -> Result<Vec<RustPlacedDeclaration>, RustCargoRouteError> {
        self.analyzer_store()
            .rust_traits_implemented_by(
                declaration.blob,
                declaration.declaration,
                &declaration.rel_path,
            )
            .map(placed_declarations)
            .map_err(|error| {
                self.inner.record_store_error(error.context(format!(
                    "reading Rust traits implemented by {declaration:?}"
                )));
                RustCargoRouteError::Unavailable
            })
    }

    fn rust_types_implementing(
        &self,
        declaration: &RustPlacedDeclaration,
    ) -> Result<Vec<RustPlacedDeclaration>, RustCargoRouteError> {
        self.analyzer_store()
            .rust_types_implementing(
                declaration.blob,
                declaration.declaration,
                &declaration.rel_path,
            )
            .map(placed_declarations)
            .map_err(|error| {
                self.inner.record_store_error(
                    error.context(format!("reading Rust types implementing {declaration:?}")),
                );
                RustCargoRouteError::Unavailable
            })
    }

    fn rust_trait_impl_rows(
        &self,
        declaration: &RustPlacedDeclaration,
    ) -> Result<Vec<RustTraitImplRow>, RustCargoRouteError> {
        self.analyzer_store()
            .rust_trait_impl_rows(
                declaration.blob,
                declaration.declaration,
                &declaration.rel_path,
            )
            .map(|rows| {
                rows.into_iter()
                    .map(|row| RustTraitImplRow {
                        impl_blob: row.impl_blob,
                        impl_rel_path: row.impl_rel_path,
                        impl_declaration: row.impl_declaration,
                        subject: row.subject.map(|(blob, declaration, rel_path)| {
                            RustPlacedDeclaration {
                                rel_path,
                                blob,
                                declaration,
                            }
                        }),
                    })
                    .collect()
            })
            .map_err(|error| {
                self.inner.record_store_error(
                    error.context(format!("reading Rust impl rows for trait {declaration:?}")),
                );
                RustCargoRouteError::Unavailable
            })
    }

    fn rust_traits_of_impl(
        &self,
        impl_item: &RustPlacedDeclaration,
    ) -> Result<Vec<RustPlacedDeclaration>, RustCargoRouteError> {
        self.analyzer_store()
            .rust_traits_of_impl(impl_item.blob, impl_item.declaration, &impl_item.rel_path)
            .map(placed_declarations)
            .map_err(|error| {
                self.inner.record_store_error(error.context(format!(
                    "reading the Rust traits stated by impl {impl_item:?}"
                )));
                RustCargoRouteError::Unavailable
            })
    }

    fn rust_item_macro_decisions(
        &self,
        file: &ProjectFile,
    ) -> Result<Vec<brokk_bifrost_rust::graph_support::RustItemMacroDecision>, RustCargoRouteError>
    {
        let blob = self
            .live_blobs()
            .oid_for_path(file)
            .ok_or(RustCargoRouteError::Unavailable)?;
        let rel_path = crate::path_utils::rel_path_string(file);
        self.analyzer_store()
            .rust_item_macro_decisions(blob, &rel_path)
            .map(|rows| {
                rows.into_iter()
                    .map(
                        |row| brokk_bifrost_rust::graph_support::RustItemMacroDecision {
                            invocation:
                                brokk_bifrost_core::analyzer::source_facts::SourceOccurrenceId::new(
                                    row.invocation,
                                ),
                            name: row.name,
                            decided: row.decided,
                        },
                    )
                    .collect()
            })
            .map_err(|error| {
                self.inner.record_store_error(
                    error.context(format!("reading the Rust item macro decisions of {file:?}")),
                );
                RustCargoRouteError::Unavailable
            })
    }

    fn rust_macro_expansion_blobs(
        &self,
        names: &[String],
    ) -> Result<Vec<brokk_bifrost_rust::graph_support::RustMacroExpansionBlob>, RustCargoRouteError>
    {
        self.analyzer_store()
            .rust_macro_expansion_blobs(names)
            .map(|rows| {
                rows.into_iter()
                    .map(
                        |row| brokk_bifrost_rust::graph_support::RustMacroExpansionBlob {
                            blob: row.blob,
                            via: row.via,
                        },
                    )
                    .collect()
            })
            .map_err(|error| {
                self.inner.record_store_error(error.context(format!(
                    "reading the Rust macro expansion candidates for {names:?}"
                )));
                RustCargoRouteError::Unavailable
            })
    }

    fn rust_trait_impl_spellings(
        &self,
        declaration: &RustPlacedDeclaration,
    ) -> Result<Vec<String>, RustCargoRouteError> {
        self.analyzer_store()
            .rust_trait_impl_spellings(
                declaration.blob,
                declaration.declaration,
                &declaration.rel_path,
            )
            .map_err(|error| {
                self.inner.record_store_error(error.context(format!(
                    "reading Rust trait impl spellings for {declaration:?}"
                )));
                RustCargoRouteError::Unavailable
            })
    }

    fn rust_alias_blobs_mentioning(
        &self,
        identifier: &str,
    ) -> Result<Vec<git2::Oid>, RustCargoRouteError> {
        self.analyzer_store()
            .rust_alias_blobs_mentioning("rust", identifier)
            .map_err(|error| {
                self.inner.record_store_error(error.context(format!(
                    "reading Rust alias blobs mentioning {identifier:?}"
                )));
                RustCargoRouteError::Unavailable
            })
    }

    fn rust_unresolved_trait_impl_files(
        &self,
        spelling: &str,
    ) -> Result<Vec<RustUnresolvedImpl>, RustCargoRouteError> {
        self.analyzer_store()
            .rust_unresolved_trait_impl_files(spelling)
            .map(|rows| {
                rows.into_iter()
                    .map(
                        |(impl_blob, impl_rel_path, impl_declaration)| RustUnresolvedImpl {
                            impl_blob,
                            impl_rel_path,
                            impl_declaration,
                        },
                    )
                    .collect()
            })
            .map_err(|error| {
                self.inner.record_store_error(error.context(format!(
                    "reading unbound Rust trait impls spelled {spelling:?}"
                )));
                RustCargoRouteError::Unavailable
            })
    }

    fn rust_identifier_occurrence_blobs(
        &self,
        identifier: &str,
    ) -> Result<Vec<(git2::Oid, u32)>, RustCargoRouteError> {
        self.analyzer_store()
            .rust_identifier_occurrence_blobs("rust", identifier)
            .map_err(|error| {
                self.inner.record_store_error(error.context(format!(
                    "reading Rust identifier occurrences for {identifier:?}"
                )));
                RustCargoRouteError::Unavailable
            })
    }

    fn rust_include_blobs(&self, file_name: &str) -> Result<Vec<git2::Oid>, RustCargoRouteError> {
        self.analyzer_store()
            .rust_include_blobs("rust", file_name)
            .map_err(|error| {
                self.inner.record_store_error(
                    error.context(format!("reading Rust include candidates for {file_name:?}")),
                );
                RustCargoRouteError::Unavailable
            })
    }

    fn rust_include_host_blobs(&self) -> Result<Vec<git2::Oid>, RustCargoRouteError> {
        self.analyzer_store()
            .rust_include_host_blobs("rust")
            .map_err(|error| {
                self.inner
                    .record_store_error(error.context("reading Rust include hosts"));
                RustCargoRouteError::Unavailable
            })
    }

    fn rust_declaration_facts_of(
        &self,
        file: &ProjectFile,
    ) -> Result<Arc<RustDeclarationFacts>, RustCargoRouteError> {
        self.rust_declaration_facts_of(file)
    }

    fn canonical_rust_hierarchy_source_facts(
        &self,
        file: &ProjectFile,
        keep_going: &dyn Fn() -> bool,
    ) -> Result<Arc<RustHierarchySourceFacts>, RustCargoRouteError> {
        self.canonical_rust_hierarchy_source_facts(file, keep_going)
    }

    fn live_blobs(&self) -> Arc<dyn RustLiveBlobs> {
        Arc::new(LiveSnapshotBlobs(self.live_path_snapshot()))
    }

    fn walk_caches(&self) -> &Arc<RustWalkCaches> {
        &self.walk_caches
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
    /// Forwarded so the request-scoped memo on the inner analyzer answers
    /// (#2679); the trait default would rebuild uncached per call.
    fn class_range_index(
        &self,
        file: &ProjectFile,
    ) -> std::sync::Arc<brokk_bifrost_core::analyzer::usages::inverted_edges::ClassRangeIndex> {
        self.inner.class_range_index(file)
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

    fn declarations_sharing_name(&self, unit: &CodeUnit) -> Vec<CodeUnit> {
        self.inner.declarations_sharing_name(unit)
    }

    fn declarations(&self, file: &ProjectFile) -> BTreeSet<CodeUnit> {
        self.inner.declarations(file)
    }

    fn declares(&self, file: &ProjectFile, unit: &CodeUnit) -> bool {
        self.inner.declares(file, unit)
    }

    fn declarations_named(&self, file: &ProjectFile, identifier: &str) -> Vec<CodeUnit> {
        self.inner.declarations_named(file, identifier)
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
    crate::analyzer::i_analyzer::forward_relational_definition_batch!();

    #[cfg(any(test, feature = "test-support"))]
    fn test_hooks(&self) -> &dyn crate::analyzer::AnalyzerTestHooks {
        self
    }

    crate::analyzer::i_analyzer::forward_file_identity_invalidation!();

    fn working_tree_identity(&self) -> Option<std::sync::Arc<crate::gitblob::WorkingTreeIdentity>> {
        self.inner.working_tree_identity()
    }

    fn abstract_member_implementations(&self, code_unit: &CodeUnit) -> Option<Vec<CodeUnit>> {
        match self.rust_trait_member_implementations(code_unit) {
            Ok(value) => value,
            Err(error) => {
                self.record_hierarchy_error(error);
                None
            }
        }
    }

    fn begin_query(&self, context: &Arc<crate::analyzer::AnalyzerQueryContext>) {
        self.inner.begin_query(context);
    }

    fn end_query(&self, context: &Arc<crate::analyzer::AnalyzerQueryContext>) {
        self.inner.end_query(context);
    }

    fn prefetch_definitions(&self, fq_names: &[String]) {
        self.inner.prefetch_definitions(fq_names);
    }

    fn record_query_failure(&self, error: crate::analyzer::store::StoreError) {
        self.inner.record_query_failure(error);
    }

    fn workspace_file_index_cell(&self) -> Option<crate::analyzer::WorkspaceFileIndexCell> {
        self.inner.workspace_file_index_cell()
    }

    fn definition_lookup_memo(
        &self,
    ) -> Option<std::sync::Arc<crate::analyzer::DefinitionLookupMemo>> {
        self.inner.definition_lookup_memo()
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
    ///
    /// The hierarchy half builds on the dedicated build pool (#1772), so this
    /// scope's own thread only parks on it: neither the warm nor a request
    /// that reaches the same memo spends a global-pool worker on the build's
    /// parallelism.
    fn warm_query_indexes(&self) {
        self.warm_usage_facts();
    }

    fn query_indexes_warm(&self) -> bool {
        self.rust_usage_facts_warm()
    }

    fn update(&self, changed_files: &BTreeSet<ProjectFile>) -> Self {
        // Before the early return: a `Cargo.toml` edit renames a crate without
        // changing a single Rust source, so the manifest memos must be dropped
        // even on the update that hands back a clone.
        crate_naming::invalidate();
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
            module_route_fact_fallback_count: Arc::new(AtomicUsize::new(0)),
            rust_usage_facts: build_weighted_cache(self.memo_budget / 8, weight_rust_usage_facts),
            declaration_facts: build_weighted_cache(
                self.memo_budget / 16,
                weight_declaration_facts,
            ),
            declaration_source_properties: build_weighted_cache(
                self.memo_budget / 16,
                weight_declaration_source_properties,
            ),
            rust_hierarchy_source_facts: build_weighted_cache(
                self.memo_budget / 16,
                weight_rust_hierarchy_source_facts,
            ),
            fact_catch_up: Arc::new(fact_catch_up::RustFactCatchUp::new()),
            walk_caches: Arc::new(RustWalkCaches::new(self.memo_budget)),
        }
    }

    fn update_all(&self) -> Self {
        crate_naming::invalidate();
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
            module_route_fact_fallback_count: Arc::new(AtomicUsize::new(0)),
            rust_usage_facts: build_weighted_cache(self.memo_budget / 8, weight_rust_usage_facts),
            declaration_facts: build_weighted_cache(
                self.memo_budget / 16,
                weight_declaration_facts,
            ),
            declaration_source_properties: build_weighted_cache(
                self.memo_budget / 16,
                weight_declaration_source_properties,
            ),
            rust_hierarchy_source_facts: build_weighted_cache(
                self.memo_budget / 16,
                weight_rust_hierarchy_source_facts,
            ),
            fact_catch_up: Arc::new(fact_catch_up::RustFactCatchUp::new()),
            walk_caches: Arc::new(RustWalkCaches::new(self.memo_budget)),
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

    fn member_family_provider(&self) -> Option<&dyn crate::analyzer::usages::MemberFamilyProvider> {
        Some(self)
    }

    fn structural_fact_providers(
        &self,
    ) -> Vec<&dyn crate::analyzer::structural::StructuralFactProvider> {
        self.inner.structural_fact_providers()
    }

    fn snapshot_caches(&self) -> Option<&crate::analyzer::AnalyzerSnapshotCaches> {
        Some(self.inner.snapshot_caches())
    }

    fn workspace_content_identities(
        &self,
    ) -> Option<crate::analyzer::content_identity::WorkspaceContentIdentities> {
        self.inner.workspace_content_identities()
    }

    fn workspace_fact_indexes(
        &self,
    ) -> Vec<&dyn crate::analyzer::read_verification::WorkspaceFactIndex> {
        self.inner.workspace_fact_indexes()
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
        match self.cargo_routes() {
            Ok(routes) => routes.file_is_test_only(file),
            // This legacy boolean capability cannot carry availability. The
            // route producer records the structured store failure on the query
            // scope, which must reject the enclosing result; do not cache it.
            Err(RustCargoRouteError::Unavailable) => false,
            Err(RustCargoRouteError::Cancelled) => {
                unreachable!("unbounded Cargo-route lookup cannot cancel")
            }
        }
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

    fn reset_relational_definition_batch_call_count_for_test(&self) {
        self.inner
            .test_hooks()
            .reset_relational_definition_batch_call_count_for_test();
    }

    fn relational_definition_batch_call_count_for_test(&self) -> usize {
        self.inner
            .test_hooks()
            .relational_definition_batch_call_count_for_test()
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

static RUST_USAGE_STRATEGY: RustNativeUsageStrategy = RustNativeUsageStrategy;

pub(crate) struct RustSupport;

/// Expand `Path::new` to `std::path::Path::new` when the file's `use`
/// declarations bind `Path` (#2596, the Rust analog of Java's #2364).
///
/// The expansion reads the parser-derived import binders the store already
/// holds: a binder's `local_name` is the name written at the call site
/// (`alias ?? identifier`), and its structured segments are the path it binds
/// to. Nothing here parses source text or reconstructs a path from the raw
/// `use` snippet.
///
/// The binder has to be a proof, not a spelling. Its leading segment must name
/// no workspace declaration in the scope that holds the `use`, which is the
/// question the Rust resolver answers for a written-out scoped path (see
/// [`rust_import_binder_external_callee`]). A workspace `std` module therefore
/// leaves the call it shadows unresolved instead of letting the binder's text
/// borrow a sysroot summary (#3484). The check needs the parsed file and the
/// exact source snapshot the call site was classified against; without them no
/// binder expands.
///
/// A callee whose owner is already multi-segment carries its own qualification
/// and is left alone. A single-segment import (`use foo;`, `extern crate foo;`)
/// adds no qualification and is skipped. Every other binder of that local name
/// has to prove this one identity: a binder that proves a different owner
/// answers nothing rather than picking one, and so does a binder that proves
/// nothing at all, whether because a workspace declaration or boundary owns the
/// path or because it is one of two mutually exclusive `#[cfg]` alternatives
/// (see `a_rust_cfg_disjoint_owner_binding_proves_no_external_identity`).
/// Nothing is published from an owner name the file itself leaves open.
///
/// A binder is read where its `use` declaration is in scope, not wherever the
/// file happens to spell the name: see
/// [`rust_import_binder_visible_at_byte`].
fn expand_rust_imported_external_callee(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    _callee_text: &str,
    site: Option<&ExternalCalleeSite<'_>>,
) -> Option<ImportedExternalCallee> {
    let site = site?;
    let callee = external_calls::call_path(site.tree, site.callee_start_byte)?;
    let segments = brokk_bifrost_rust::graph_support::rust_path_segments(callee)?;
    let [owner, member] = segments.as_slice() else {
        return None;
    };
    let owner = brokk_bifrost_rust::declarations::rust_node_text(*owner, site.source);
    let member = brokk_bifrost_rust::declarations::rust_node_text(*member, site.source);
    // The declared callable this binder proves has to accept the written call,
    // so the expansion reads the call's written argument count from the same
    // parsed tree the callee reference came from. A callee whose call does not
    // parse is not proof of anything.
    let parameter_count = rust_call_written_arity(site.tree, site.callee_start_byte)?;
    let provider = analyzer.import_analysis_provider_for_file(file)?;
    let scope = AnalyzerQueryScope::new(analyzer);
    let mut expanded: Option<(ExactExternalCallProof, ResolverOwnedExternalCalleeIdentity)> = None;
    for import in provider.import_info_of(scope.token(), file) {
        let binding_name = rust_import_binding_name(&import);
        if binding_name.is_glob() || binding_name.named() != Some(owner) {
            continue;
        }
        // Only an owner path can carry the qualification; a `use foo;`
        // binder has nothing to expand, exactly as before.
        let path = match import.path.as_ref() {
            Some(path) if path.segments.len() >= 2 => path,
            _ => continue,
        };
        // The binder is evidence only where the `use` declaration is in
        // scope. A module-owned `use` binds its name inside that module's
        // lexical extent -- which is exactly what `lexical_scopes` records --
        // so a binder written in a sibling module names nothing at this call,
        // and letting it answer would either veto a real identity or, when it
        // binds the same path, prove an identity the call never wrote.
        if !rust_import_binder_visible_at_byte(path, site.callee_start_byte) {
            continue;
        }
        // A binder that names the local owner but proves no external identity
        // is evidence against the expansion, so it ends the whole answer
        // rather than extending the loop.
        let proof = rust_import_binder_external_callee(
            analyzer,
            scope.token(),
            file,
            site,
            &import,
            member,
            parameter_count,
        )?;
        match &expanded {
            Some(existing) if *existing == proof => {}
            Some(_) => return None,
            None => expanded = Some(proof),
        }
    }
    // The binder selected one callable in the activated model, so the call
    // carries that callable's exact proof and owner/member identity into the
    // common dispatch path rather than a spelling a later stage has to
    // re-interpret (#3484).
    expanded.map(|(proof, identity)| ImportedExternalCallee::proven(proof, identity))
}

/// Whether the parser-derived `use` declaration behind `path` binds a name
/// that is in scope at `call_start_byte`.
///
/// `lexical_scopes` records the containers the parser found around the
/// declaration, outermost first, so a binder is in scope exactly where the
/// innermost recorded container reaches. A module-owned `use` therefore names
/// something only inside that module's body (and the modules nested in it,
/// which is why containment, not equality, is the test). A top-level `use`
/// records no container to constrain it and is visible anywhere in the file.
///
/// Without this filter a `use` written inside a sibling inline module answers
/// for calls in other modules, where the name it binds is not in scope: the
/// binder can then veto a real identity or, when it binds the same path, hand
/// a call an identity it never wrote (#3484).
fn rust_import_binder_visible_at_byte(path: &StructuredImportPath, call_start_byte: usize) -> bool {
    path.lexical_scopes
        .iter()
        .all(|scope| scope.start_byte <= call_start_byte && call_start_byte < scope.end_byte)
}

impl LanguageSupport for RustSupport {
    fn language(&self) -> Language {
        Language::Rust
    }

    fn procedure_syntax_roles(&self) -> Option<crate::analyzer::languages::ProcedureSyntaxRoles> {
        Some(semantic::PROCEDURE_SYNTAX_ROLES)
    }

    fn bind_generated_symbols(
        &self,
        file: &ProjectFile,
        source: &str,
        symbols: &mut [crate::analyzer::semantic_model::SemanticModelSymbol],
    ) {
        generated_model::bind_generated_functions(file, source, symbols);
    }

    fn call_argument_conversion_prover(
        &self,
    ) -> Option<&'static dyn crate::analyzer::usages::call_conversion::CallArgumentConversionProver>
    {
        Some(&call_conversion::CALL_ARGUMENT_CONVERSION_PROVER)
    }

    fn selected_macro_source_rows(
        &self,
    ) -> Option<&'static dyn crate::analyzer::store::resolution_operation::SelectedMacroSourceRows>
    {
        Some(&source_storage::RustMacroSourceRows)
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

    fn reference_plugin(&self) -> crate::analyzer::languages::ReferenceLanguagePlugin {
        crate::analyzer::languages::ReferenceLanguagePlugin::native(
            &RUST_USAGE_STRATEGY,
            &native_graph::RustNativeWorkspaceGraphProvider,
        )
    }

    fn call_relation_provider(
        &self,
    ) -> Option<&'static dyn crate::analyzer::usages::call_relations::CallRelationProvider> {
        Some(&native_call_projection::RustNativeCallRelations)
    }

    fn rename_provider(&self) -> Option<&'static dyn crate::symbol_rename::RenameProvider> {
        Some(&native_rename::RustNativeRenameProvider)
    }

    fn selected_inverse_reference_provider(
        &self,
    ) -> Option<
        &'static dyn crate::analyzer::structural::reference_edges::SelectedInverseReferenceProvider,
    > {
        Some(&selected_shadow::RustNativeSelectedInverseProvider)
    }

    fn qualified_call_separator(&self) -> &'static str {
        "::"
    }

    fn expand_imported_external_callee(
        &self,
        analyzer: &dyn IAnalyzer,
        file: &ProjectFile,
        callee_text: &str,
        site: Option<&ExternalCalleeSite<'_>>,
    ) -> Option<ImportedExternalCallee> {
        expand_rust_imported_external_callee(analyzer, file, callee_text, site)
    }

    fn dead_code(&self) -> DeadCodeSupport {
        DeadCodeSupport {
            strategy: Some(&RUST_USAGE_STRATEGY),
            bulk: None,
        }
    }

    fn dead_code_needs_precise_scan(&self, analyzer: &dyn IAnalyzer, candidate: &CodeUnit) -> bool {
        resolve_analyzer::<RustAnalyzer>(analyzer).is_some_and(|rust| {
            (candidate.is_function() || candidate.is_field() || rust.is_type_alias(candidate))
                && rust.parent_of(candidate).is_some()
        })
    }

    fn structural_receiver(&self) -> Option<&'static dyn StructuralReceiverResolver> {
        Some(&RustSupport)
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

impl StructuralReceiverResolver for RustSupport {
    fn resolve_type_bounded(
        &self,
        query: BoundedReceiverQuery<'_>,
    ) -> BoundedResolution<TypeLookupOutcome> {
        native_points::resolve_rust_type_bounded(query)
    }

    fn resolve_definition_bounded(
        &self,
        query: BoundedReceiverQuery<'_>,
    ) -> BoundedResolution<DefinitionLookupOutcome> {
        native_points::resolve_rust_definition_bounded(query)
    }
}

/// The generation boundary for crate naming.
///
/// `brokk_bifrost_rust::crate_naming` memoizes the manifest walk for a whole
/// analyzer generation instead of stat-ing a `Cargo.toml` on every question
/// (#2632), so the `invalidate` calls above are the only thing that makes a
/// manifest edit visible. This test pins that wiring: without it a renamed
/// crate would keep its old name until the process exited.
#[cfg(test)]
mod tests {
    use crate::analyzer::{IAnalyzer, Language, ProjectFile, TestProject};
    use brokk_bifrost_rust::declarations::rust_package_name;
    use std::collections::BTreeSet;

    fn write(root: &std::path::Path, relative: &str, contents: &str) {
        let path = root.join(relative);
        std::fs::create_dir_all(path.parent().expect("parent")).expect("create dirs");
        std::fs::write(&path, contents).expect("write fixture");
    }

    fn rust_analyzer(root: &std::path::Path) -> super::RustAnalyzer {
        super::RustAnalyzer::from_project(TestProject::new(root.to_path_buf(), Language::Rust))
    }

    #[test]
    fn a_manifest_rename_reaches_naming_at_the_next_generation() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().canonicalize().expect("canonical root");
        write(
            &root,
            "Cargo.toml",
            "[package]\nname = \"before\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        );
        write(&root, "src/lib.rs", "pub struct Marker;\n");
        let library = ProjectFile::new(root.clone(), "src/lib.rs");

        let analyzer = rust_analyzer(&root);
        assert_eq!(rust_package_name(&library), "before");

        write(
            &root,
            "Cargo.toml",
            "[package]\nname = \"after\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        );
        // A manifest edit changes no Rust source, so this is the `update` that
        // hands back a clone. The naming memo must still be dropped.
        let updated = analyzer.update(&BTreeSet::from([ProjectFile::new(
            root.clone(),
            "Cargo.toml",
        )]));
        assert_eq!(
            rust_package_name(&library),
            "after",
            "update starts a generation, so it re-reads the manifest",
        );
        drop(updated);

        write(
            &root,
            "Cargo.toml",
            "[package]\nname = \"renamed-again\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        );
        let rebuilt = rust_analyzer(&root);
        assert_eq!(
            rust_package_name(&library),
            "renamed_again",
            "constructing an analyzer starts a generation too",
        );
        drop(rebuilt);
    }
}

#[cfg(test)]
mod foreign_file_tests {
    use crate::analyzer::{AnalyzerQueryScope, Language, ProjectFile, TestProject};

    /// Asking the Rust analyzer for a file it does not own is not a store
    /// failure.
    ///
    /// A recorded store error fails the whole MCP request
    /// (`searchtools_service.rs`, "Analyzer store failure while running ..."),
    /// so a mixed-language `usage_graph` that named only Rust paths exited 1
    /// on a C++ header that some other read had reached. The Rust adapter
    /// reports "not mine" for a foreign file and leaves the request intact.
    #[test]
    fn a_foreign_file_is_unavailable_to_rust_without_failing_the_request() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().canonicalize().expect("canonical root");
        std::fs::create_dir_all(root.join("src")).expect("create src");
        std::fs::write(
            root.join("Cargo.toml"),
            "[package]\nname = \"foreign\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
        )
        .expect("write manifest");
        std::fs::write(root.join("src/lib.rs"), "pub fn target() {}\n").expect("write Rust");
        std::fs::write(root.join("src/widget.h"), "struct Widget { int v; };\n")
            .expect("write header");
        let analyzer =
            super::RustAnalyzer::from_project(TestProject::new(root.clone(), Language::Rust));

        let scope = AnalyzerQueryScope::new(&analyzer);
        let header = ProjectFile::new(root.clone(), "src/widget.h");
        let outcome = analyzer.canonical_rust_hierarchy_source_facts(&header, &|| true);
        assert!(
            matches!(outcome, Err(super::RustCargoRouteError::Unavailable)),
            "a foreign file has no canonical Rust source"
        );
        assert!(
            scope.store_error().is_none(),
            "a foreign file must not poison the request: {:?}",
            scope.store_error()
        );

        // A Rust file the snapshot does know still answers, so the guard did
        // not silence the ownership test itself.
        let library = ProjectFile::new(root, "src/lib.rs");
        assert!(
            analyzer
                .canonical_rust_hierarchy_source_facts(&library, &|| true)
                .is_ok()
        );
    }
}
