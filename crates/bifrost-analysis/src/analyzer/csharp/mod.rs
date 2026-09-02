//! The analyzer-owned shim over [`brokk_bifrost_csharp`].
//!
//! What lives here is everything the language crate cannot name: the
//! [`CSharpAnalyzer`] newtype and its generation-owned bounded caches and lazy
//! cells; the accessors that implement
//! [`graph_support::CSharpSource`] out of them; the `CSharpAdapter`
//! forwarding shell; the `IAnalyzer`/`CodeUnitIndex` impls; and the
//! `LanguageSupport` SPI block.

mod adapter;
mod cache;
mod clones;
mod compilation;
mod dependency_discovery;
pub(crate) mod diagnostics;
pub mod external;
mod hierarchy_provider;
mod imports;
mod semantic;
mod structural;
mod test_classification;
use crate::analyzer::Range;
use crate::analyzer::structural::BoundaryStatus;
use brokk_bifrost_core::analyzer::query_token::QueryToken;

// The language halves of the type-resolution and hierarchy logic moved to
// `brokk-bifrost-csharp`; re-exporting the modules keeps every
// `crate::analyzer::csharp::{graph_support,hierarchy}::` call site in the
// definition route, the type route and the usage graph pointing at the same
// paths.
pub(crate) use brokk_bifrost_csharp::{graph_support, hierarchy};

// C# language knowledge lives in `brokk-bifrost-csharp`; these keep their
// historical `crate::analyzer::csharp::` paths for the analysis-side consumers
// (the re-export hub in `analyzer/mod.rs`, the definition and type routes, the
// usage graph, and this crate's own C# modules).
pub(crate) use brokk_bifrost_csharp::syntax::{
    csharp_attribute_name_node, csharp_attribute_type_names, csharp_callable_arity,
    csharp_conditional_member_access, csharp_member_name, csharp_method_generic_arity,
    csharp_normalize_full_name, csharp_source_identifier, csharp_type_node_identity,
};
pub use brokk_bifrost_csharp::syntax::{csharp_source_name_segment, strip_csharp_generic_arity};

use crate::analyzer::clone_detection::{
    CloneCandidateProfile, detect_structural_clone_smells, refine_clone_similarity_with_ast,
};
use crate::analyzer::common::language_for_file as file_language;
use crate::analyzer::languages::{
    BoundedReceiverQuery, DeadCodeBulkEdges, DeadCodeBulkPreflight, DeadCodeBulkProof,
    DeadCodeRouting, DeadCodeSupport, EdgePassId, EdgeSiteScanCtx, EdgeWeightScanCtx,
    LanguageEdgePass, LanguageEdgeSites, LanguageEdgeWeights, LanguageSupport,
    StructuralReceiverResolver, analyzable_file_count, candidate_fqns,
    fqn_has_multiple_function_definitions,
};
use crate::analyzer::store::LimitedQueryRows;
use crate::analyzer::usages::csharp_graph::{
    CSharpUsageGraphStrategy, build_csharp_usage_edge_weights,
    build_inbound_csharp_usage_edges_with_completeness, build_rooted_csharp_usage_edges,
};
use crate::analyzer::usages::get_definition::{
    BoundedResolution, DefinitionLookupOutcome, resolve_csharp_bounded,
};
use crate::analyzer::usages::get_type::{TypeLookupOutcome, resolve_csharp_type_bounded};
use crate::analyzer::usages::inverted_edges::cached_dead_code_usage_edges;
use crate::analyzer::usages::workspace_graph::UsageEcosystem;
use crate::analyzer::{
    AnalyzerConfig, AnalyzerDefinitionLookup, AnalyzerStoreContext, BoundedDefinitionLookup,
    BuildProgress, CSharpAnalyzerConfig, CodeUnit, ForwardQueryProvider, IAnalyzer,
    ImportAnalysisProvider, Language, Project, ProjectFile, SignatureMetadata, TestAssertionSmell,
    TestAssertionWeights, TestDetectionProvider, TreeSitterAnalyzer, TypeHierarchyProvider,
    resolve_analyzer,
};
use crate::hash::{HashMap, HashSet};
use crate::{CloneSmell, CloneSmellWeights};
use std::collections::BTreeSet;
use std::sync::Arc;

use crate::analyzer::{AnalyzerQueryScope, QueryScope};
pub(crate) use adapter::CSharpAdapter;
use brokk_bifrost_csharp::dead_code::{
    csharp_constructor_candidate, csharp_unsafe_using_member_forms_present,
};
use brokk_bifrost_csharp::test_detection::detect_csharp_test_assertion_smells;
use cache::{CSharpMemoCaches, PersistedFqnLookup};
use clones::build_csharp_clone_candidate_data;
use external::{CSharpExternalDeclarationIndex, CSharpExternalMember, CSharpExternalType};
use graph_support::CSharpSource;

fn limited_known_values<T>(
    len: usize,
    values: impl IntoIterator<Item = T>,
    limit: usize,
) -> LimitedQueryRows<T> {
    if limit == 0 {
        return LimitedQueryRows::incomplete(Vec::new(), 0);
    }
    let inspected = len.min(limit);
    let rows = values.into_iter().take(limit).collect();
    if len > limit {
        LimitedQueryRows::incomplete(rows, inspected)
    } else {
        LimitedQueryRows::complete(rows, inspected)
    }
}

pub(crate) use dependency_discovery::{
    is_csharp_dependency_input, is_csharp_dependency_input_path,
};

#[derive(Clone)]
pub struct CSharpAnalyzer {
    inner: TreeSitterAnalyzer<CSharpAdapter>,
    memo_caches: Arc<CSharpMemoCaches>,
    csharp_config: CSharpAnalyzerConfig,
    external_index: Arc<std::sync::OnceLock<CSharpExternalDeclarationIndex>>,
}

crate::analyzer::impl_forward_query_provider!(CSharpAnalyzer);

impl CSharpAnalyzer {
    pub(crate) fn clone_with_project(&self, project: Arc<dyn Project>) -> Self {
        let mut clone = self.clone();
        clone.inner = clone.inner.clone_with_project(project);
        clone.memo_caches = Arc::new(CSharpMemoCaches::new(self.memo_caches.budget_bytes()));
        clone.external_index = Arc::new(std::sync::OnceLock::new());
        clone
    }

    pub(crate) fn clone_for_index_warm(&self, project: Arc<dyn Project>) -> Self {
        let mut clone = self.clone();
        clone.inner = clone.inner.clone_with_project(project);
        clone
    }

    pub fn new(project: Arc<dyn Project>) -> Self {
        Self::new_with_config(project, AnalyzerConfig::default())
    }

    pub fn new_with_config(project: Arc<dyn Project>, config: AnalyzerConfig) -> Self {
        let memo_budget = config.memo_cache_budget_bytes();
        let csharp_config = config.csharp.clone();
        Self {
            inner: TreeSitterAnalyzer::new_with_config(project, CSharpAdapter, config),
            memo_caches: Arc::new(CSharpMemoCaches::new(memo_budget)),
            csharp_config,
            external_index: Arc::new(std::sync::OnceLock::new()),
        }
    }

    pub(crate) fn new_with_config_store_context(
        project: Arc<dyn Project>,
        config: AnalyzerConfig,
        store_context: AnalyzerStoreContext,
        progress: Option<BuildProgress>,
    ) -> Result<Self, crate::analyzer::store::StoreError> {
        let memo_budget = config.memo_cache_budget_bytes();
        let csharp_config = config.csharp.clone();
        let inner = TreeSitterAnalyzer::new_with_config_storage_context_and_progress(
            project,
            CSharpAdapter,
            config,
            store_context,
            progress,
        )?;
        Ok(Self {
            inner,
            memo_caches: Arc::new(CSharpMemoCaches::new(memo_budget)),
            csharp_config,
            external_index: Arc::new(std::sync::OnceLock::new()),
        })
    }

    pub fn from_project<P>(project: P) -> Self
    where
        P: Project + 'static,
    {
        Self::new(Arc::new(project))
    }

    #[doc(hidden)]
    pub fn reset_full_hydration_count_for_test(&self) {
        self.inner.reset_full_hydration_count_for_test();
    }

    #[doc(hidden)]
    pub fn full_hydration_count_for_test(&self) -> usize {
        self.inner.full_hydration_count_for_test()
    }

    pub(crate) fn declaration_candidates_by_identifier(
        &self,
        identifier: &str,
    ) -> BTreeSet<CodeUnit> {
        self.inner.lookup_declarations_by_identifier(identifier)
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

    pub(crate) fn member_candidates_for_owner(
        &self,
        owner_fqn: &str,
        name: &str,
    ) -> BTreeSet<CodeUnit> {
        self.inner.lookup_members_for_owner_name(owner_fqn, name)
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

    pub(crate) fn workspace_namespace_exists(&self, namespace: &str) -> bool {
        let key = namespace.to_string();
        self.memo_caches
            .namespace_exists
            .get_or_try_build(&key, || {
                #[cfg(any(test, feature = "test-support"))]
                self.memo_caches
                    .namespace_exists_build_count
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                self.inner.try_persisted_package_may_exist(namespace)
            })
            .is_none_or(|exists| *exists)
    }

    fn persisted_declaration_candidates_by_fqn_cached(
        &self,
        fqn: &str,
        normalized: bool,
    ) -> BTreeSet<CodeUnit> {
        let key = PersistedFqnLookup {
            name: if normalized {
                csharp_normalize_full_name(fqn)
            } else {
                fqn.to_string()
            },
            normalized,
        };
        self.memo_caches
            .persisted_fqn_candidates
            .get_or_try_build(&key, || {
                #[cfg(any(test, feature = "test-support"))]
                self.memo_caches
                    .persisted_fqn_candidate_build_count
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                self.inner
                    .try_lookup_declarations_by_persisted_fqn(&key.name, key.normalized)
            })
            .map_or_else(BTreeSet::new, |candidates| (*candidates).clone())
    }

    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn reset_visible_type_store_build_counts_for_test(&self) {
        use std::sync::atomic::Ordering;

        self.memo_caches
            .namespace_exists_build_count
            .store(0, Ordering::Relaxed);
        self.memo_caches
            .persisted_fqn_candidate_build_count
            .store(0, Ordering::Relaxed);
    }

    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn visible_type_store_build_counts_for_test(&self) -> (usize, usize) {
        use std::sync::atomic::Ordering;

        (
            self.memo_caches
                .namespace_exists_build_count
                .load(Ordering::Relaxed),
            self.memo_caches
                .persisted_fqn_candidate_build_count
                .load(Ordering::Relaxed),
        )
    }

    pub fn namespace_of_file(&self, file: &ProjectFile) -> String {
        if let Some(cached) = self.memo_caches.namespace_by_file.get(file) {
            return (*cached).clone();
        }
        let namespace = graph_support::compute_namespace_of_file(self, file);
        self.memo_caches
            .namespace_by_file
            .insert(file.clone(), Arc::new(namespace.clone()));
        namespace
    }

    /// The bounded twin of [`Self::namespace_of_file`], sharing its memo cell.
    /// Public because the two spellings are required to agree and the #1726
    /// regression test calls both against one analyzer in both orders.
    pub fn namespace_of_file_limited(
        &self,
        file: &ProjectFile,
        limit: usize,
    ) -> LimitedQueryRows<String> {
        if let Some(cached) = self.memo_caches.namespace_by_file.get(file) {
            return limited_known_values(1, std::iter::once((*cached).clone()), limit);
        }
        let batch = graph_support::compute_namespace_of_file_limited(self, file, limit);
        if batch.complete {
            let namespace = batch.rows.first().cloned().unwrap_or_default();
            self.memo_caches
                .namespace_by_file
                .insert(file.clone(), Arc::new(namespace));
        }
        batch
    }

    pub fn external_declaration_index(&self) -> &CSharpExternalDeclarationIndex {
        self.external_index.get_or_init(|| {
            CSharpExternalDeclarationIndex::build_for_project(
                &self.csharp_config,
                self.inner.project(),
            )
        })
    }

    /// The assembly declaration index *if an earlier pass already built it*.
    ///
    /// [`Self::external_declaration_index`] builds on first access, which walks
    /// the project for `project.assets.json` and decodes assembly metadata.
    /// #1615 forbids that work inside a diagnostic request, so the proof-gated
    /// ladder peeks here instead and treats an unbuilt index as an unknown
    /// boundary rather than a reason to go and build one.
    pub(crate) fn retained_external_index(&self) -> Option<&CSharpExternalDeclarationIndex> {
        self.external_index.get()
    }

    pub fn external_type_candidates(
        &self,
        token: QueryToken<'_>,
        file: &ProjectFile,
        reference: &str,
    ) -> Vec<&CSharpExternalType> {
        self.external_declaration_index().resolve_in_file(
            reference,
            &self.namespace_of_file(file),
            &self.using_namespaces_of(token, file),
            &self.using_aliases_of(token, file),
        )
    }

    /// How far a lookup for `name` from `file` could see past the workspace,
    /// and the external type it landed on when it landed on one.
    ///
    /// The C# half of boundary refinement, mirroring
    /// `JavaAnalyzer::external_boundary_evidence`: the reference is resolved
    /// against the assembly declaration index with the same file inputs
    /// [`Self::external_type_candidates`] uses. One distinct identity is
    /// [`BoundaryStatus::ExternalIndexed`] with that identity; several distinct
    /// identities are still indexed -- the name certainly exists in the
    /// compiled references -- but no single target can be reported. A miss
    /// against an index that could not read everything the build declared
    /// (incomplete discovery, or an assembly whose decode gave up part way) is
    /// [`BoundaryStatus::ExternalDeclaredUnindexed`], the same collapse the C#
    /// diagnostics pass renders as its typed suppression reasons.
    pub(crate) fn external_boundary_evidence(
        &self,
        token: QueryToken<'_>,
        file: &ProjectFile,
        name: &str,
    ) -> (BoundaryStatus, Option<String>) {
        let candidates = self.external_type_candidates(token, file, name);
        // Two assemblies publishing the same identity are one type as far as a
        // name lookup is concerned; only distinct identities are an ambiguity.
        let distinct: HashSet<&str> = candidates.iter().map(|ty| ty.fqn()).collect();
        let mut identities = distinct.into_iter();
        match (identities.next(), identities.len()) {
            (Some(fqn), 0) => return (BoundaryStatus::ExternalIndexed, Some(fqn.to_owned())),
            (Some(_), _) => return (BoundaryStatus::ExternalIndexed, None),
            (None, _) => {}
        }
        let index = self.external_declaration_index();
        if !index.is_complete() || !index.production_diagnostics().is_empty() {
            return (BoundaryStatus::ExternalDeclaredUnindexed, None);
        }
        (BoundaryStatus::ExternalUnknown, None)
    }

    pub fn external_member_candidates(
        &self,
        owner: &str,
        name: &str,
    ) -> Vec<&CSharpExternalMember> {
        self.external_declaration_index().members_named(owner, name)
    }

    pub fn using_namespaces_of(&self, token: QueryToken<'_>, file: &ProjectFile) -> Vec<String> {
        if let Some(cached) = self.memo_caches.using_namespaces.get(file) {
            return (*cached).clone();
        }
        let namespaces = graph_support::compute_using_namespaces_of(self, token, file);
        self.memo_caches
            .using_namespaces
            .insert(file.clone(), Arc::new(namespaces.clone()));
        namespaces
    }

    pub(crate) fn using_namespaces_of_limited(
        &self,
        token: QueryToken<'_>,
        file: &ProjectFile,
        limit: usize,
        mut continue_query: impl FnMut() -> bool,
    ) -> LimitedQueryRows<String> {
        if let Some(cached) = self.memo_caches.using_namespaces.get(file) {
            return limited_known_values(cached.len(), cached.iter().cloned(), limit);
        }
        let batch = graph_support::compute_using_namespaces_of_limited(
            self,
            token,
            file,
            limit,
            &mut continue_query,
        );
        if batch.complete {
            self.memo_caches
                .using_namespaces
                .insert(file.clone(), Arc::new(batch.rows.clone()));
        }
        batch
    }

    pub fn using_aliases_of(
        &self,
        token: QueryToken<'_>,
        file: &ProjectFile,
    ) -> Arc<HashMap<String, String>> {
        if let Some(cached) = self.memo_caches.using_aliases.get(file) {
            return cached;
        }
        let aliases = Arc::new(graph_support::compute_using_aliases_of(self, token, file));
        self.memo_caches
            .using_aliases
            .insert(file.clone(), Arc::clone(&aliases));
        aliases
    }

    pub(crate) fn using_aliases_of_limited(
        &self,
        token: QueryToken<'_>,
        file: &ProjectFile,
        limit: usize,
        mut continue_query: impl FnMut() -> bool,
    ) -> LimitedQueryRows<(String, String)> {
        if let Some(cached) = self.memo_caches.using_aliases.get(file) {
            return limited_known_values(
                cached.len(),
                cached
                    .iter()
                    .map(|(alias, target)| (alias.clone(), target.clone())),
                limit,
            );
        }
        let batch = graph_support::compute_using_aliases_of_limited(
            self,
            token,
            file,
            limit,
            &mut continue_query,
        );
        if batch.complete {
            self.memo_caches.using_aliases.insert(
                file.clone(),
                Arc::new(batch.rows.iter().cloned().collect::<HashMap<_, _>>()),
            );
        }
        batch
    }

    pub(crate) fn global_using_namespaces(&self, token: QueryToken<'_>) -> &HashSet<String> {
        self.memo_caches
            .global_using_namespaces
            .get_or_init(|| graph_support::compute_global_using_namespaces(self, token))
    }

    pub(crate) fn global_using_namespaces_limited(
        &self,
        limit: usize,
        mut continue_query: impl FnMut() -> bool,
    ) -> LimitedQueryRows<String> {
        if let Some(cached) = self.memo_caches.global_using_namespaces.get() {
            return limited_known_values(cached.len(), cached.iter().cloned(), limit);
        }
        let batch = graph_support::compute_global_using_namespaces_limited(
            self,
            limit,
            &mut continue_query,
        );
        if batch.complete {
            let _ = self
                .memo_caches
                .global_using_namespaces
                .set(batch.rows.iter().cloned().collect());
        }
        batch
    }

    fn global_using_aliases(&self, token: QueryToken<'_>) -> &HashMap<String, String> {
        self.memo_caches
            .global_using_aliases
            .get_or_init(|| graph_support::compute_global_using_aliases(self, token))
    }

    pub(crate) fn global_using_aliases_limited(
        &self,
        limit: usize,
        mut continue_query: impl FnMut() -> bool,
    ) -> LimitedQueryRows<(String, String)> {
        if let Some(cached) = self.memo_caches.global_using_aliases.get() {
            return limited_known_values(
                cached.len(),
                cached
                    .iter()
                    .map(|(alias, target)| (alias.clone(), target.clone())),
                limit,
            );
        }
        let batch =
            graph_support::compute_global_using_aliases_limited(self, limit, &mut continue_query);
        if batch.complete {
            let _ = self
                .memo_caches
                .global_using_aliases
                .set(batch.rows.iter().cloned().collect());
        }
        batch
    }

    pub(crate) fn global_static_using_type_names(&self, token: QueryToken<'_>) -> &[String] {
        self.memo_caches
            .global_static_using_type_names
            .get_or_init(|| graph_support::compute_global_static_using_type_names(self, token))
    }

    pub(crate) fn global_static_using_type_names_limited(
        &self,
        limit: usize,
        mut continue_query: impl FnMut() -> bool,
    ) -> LimitedQueryRows<String> {
        if let Some(cached) = self.memo_caches.global_static_using_type_names.get() {
            return limited_known_values(cached.len(), cached.iter().cloned(), limit);
        }
        let batch = graph_support::compute_global_static_using_type_names_limited(
            self,
            limit,
            &mut continue_query,
        );
        if batch.complete {
            let _ = self
                .memo_caches
                .global_static_using_type_names
                .set(batch.rows.clone());
        }
        batch
    }

    pub(crate) fn global_static_using_types(&self, token: QueryToken<'_>) -> &[CodeUnit] {
        self.memo_caches
            .global_static_using_types
            .get_or_init(|| graph_support::compute_global_static_using_types(self, token))
    }

    pub(crate) fn usage_global_static_using_types(&self, token: QueryToken<'_>) -> &[CodeUnit] {
        self.memo_caches
            .usage_global_static_using_types
            .get_or_init(|| graph_support::compute_usage_global_static_using_types(self, token))
    }
}

impl CSharpSource for CSharpAnalyzer {
    fn persisted_declaration_candidates_by_fqn(
        &self,
        fqn: &str,
        normalized: bool,
    ) -> BTreeSet<CodeUnit> {
        self.persisted_declaration_candidates_by_fqn_cached(fqn, normalized)
    }

    fn persisted_declaration_candidates_by_fqn_limited(
        &self,
        fqn: &str,
        normalized: bool,
        limit: usize,
        continue_query: &mut dyn FnMut() -> bool,
    ) -> LimitedQueryRows<CodeUnit> {
        self.inner.lookup_declarations_by_persisted_fqn_limited(
            fqn,
            normalized,
            limit,
            continue_query,
        )
    }

    fn declaration_candidates_by_identifier(&self, identifier: &str) -> BTreeSet<CodeUnit> {
        CSharpAnalyzer::declaration_candidates_by_identifier(self, identifier)
    }

    fn declaration_candidates_by_identifier_limited(
        &self,
        identifier: &str,
        limit: usize,
        continue_query: &mut dyn FnMut() -> bool,
    ) -> LimitedQueryRows<CodeUnit> {
        CSharpAnalyzer::declaration_candidates_by_identifier_limited(
            self,
            identifier,
            limit,
            continue_query,
        )
    }

    fn member_candidates_for_owner(&self, owner_fqn: &str, name: &str) -> BTreeSet<CodeUnit> {
        CSharpAnalyzer::member_candidates_for_owner(self, owner_fqn, name)
    }

    fn member_candidates_for_owner_limited(
        &self,
        owner_fqn: &str,
        name: &str,
        limit: usize,
        continue_query: &mut dyn FnMut() -> bool,
    ) -> LimitedQueryRows<CodeUnit> {
        CSharpAnalyzer::member_candidates_for_owner_limited(
            self,
            owner_fqn,
            name,
            limit,
            continue_query,
        )
    }

    fn workspace_namespace_exists(&self, namespace: &str) -> bool {
        CSharpAnalyzer::workspace_namespace_exists(self, namespace)
    }

    fn with_usage_definitions(
        &self,
        _token: QueryToken<'_>,
        read: &mut dyn FnMut(&dyn BoundedDefinitionLookup),
    ) {
        let lookup = AnalyzerDefinitionLookup::new(self, Language::CSharp);
        read(&lookup);
    }

    fn all_files(&self) -> Vec<ProjectFile> {
        self.inner.all_files()
    }

    fn package_name_of(&self, file: &ProjectFile) -> Option<String> {
        self.inner.package_name_of(file)
    }

    fn file_namespace_hint_limited(
        &self,
        file: &ProjectFile,
        limit: usize,
    ) -> LimitedQueryRows<String> {
        self.inner.file_namespace_hint_limited(file, limit)
    }

    fn import_info_of_limited(
        &self,
        token: QueryToken<'_>,
        file: &ProjectFile,
        limit: usize,
    ) -> LimitedQueryRows<crate::analyzer::ImportInfo> {
        self.inner.import_info_of_limited(token, file, limit)
    }

    fn workspace_import_info_limited(
        &self,
        limit: usize,
        continue_query: &mut dyn FnMut() -> bool,
    ) -> LimitedQueryRows<crate::analyzer::ImportInfo> {
        let scope = AnalyzerQueryScope::new(self);
        let token = scope.token();
        self.inner
            .workspace_import_info_limited(token, limit, continue_query)
    }

    fn raw_supertypes_of(&self, code_unit: &CodeUnit) -> Vec<String> {
        self.inner.raw_supertypes_of(code_unit)
    }

    fn raw_supertypes_limited(
        &self,
        code_unit: &CodeUnit,
        limit: usize,
    ) -> LimitedQueryRows<String> {
        CSharpAnalyzer::raw_supertypes_limited(self, code_unit, limit)
    }

    fn signature_metadata_limited(
        &self,
        code_unit: &CodeUnit,
        limit: usize,
    ) -> LimitedQueryRows<SignatureMetadata> {
        CSharpAnalyzer::signature_metadata_limited(self, code_unit, limit)
    }

    fn type_identifiers_of(&self, file: &ProjectFile) -> Option<HashSet<String>> {
        self.inner.type_identifiers_of(file)
    }

    fn namespace_of_file(&self, file: &ProjectFile) -> String {
        CSharpAnalyzer::namespace_of_file(self, file)
    }

    fn namespace_of_file_limited(
        &self,
        file: &ProjectFile,
        limit: usize,
    ) -> LimitedQueryRows<String> {
        CSharpAnalyzer::namespace_of_file_limited(self, file, limit)
    }

    fn using_namespaces_of(&self, file: &ProjectFile) -> Vec<String> {
        let scope = AnalyzerQueryScope::new(self);
        let token = scope.token();
        CSharpAnalyzer::using_namespaces_of(self, token, file)
    }

    fn using_namespaces_of_limited(
        &self,
        file: &ProjectFile,
        limit: usize,
        continue_query: &mut dyn FnMut() -> bool,
    ) -> LimitedQueryRows<String> {
        let scope = AnalyzerQueryScope::new(self);
        let token = scope.token();
        CSharpAnalyzer::using_namespaces_of_limited(self, token, file, limit, continue_query)
    }

    fn using_aliases_of(&self, file: &ProjectFile) -> Arc<HashMap<String, String>> {
        let scope = AnalyzerQueryScope::new(self);
        let token = scope.token();
        CSharpAnalyzer::using_aliases_of(self, token, file)
    }

    fn using_aliases_of_limited(
        &self,
        file: &ProjectFile,
        limit: usize,
        continue_query: &mut dyn FnMut() -> bool,
    ) -> LimitedQueryRows<(String, String)> {
        let scope = AnalyzerQueryScope::new(self);
        let token = scope.token();
        CSharpAnalyzer::using_aliases_of_limited(self, token, file, limit, continue_query)
    }

    fn global_static_using_type_names(&self) -> &[String] {
        let scope = AnalyzerQueryScope::new(self);
        let token = scope.token();
        CSharpAnalyzer::global_static_using_type_names(self, token)
    }

    fn global_static_using_type_names_limited(
        &self,
        limit: usize,
        continue_query: &mut dyn FnMut() -> bool,
    ) -> LimitedQueryRows<String> {
        CSharpAnalyzer::global_static_using_type_names_limited(self, limit, continue_query)
    }

    fn global_static_using_types(&self) -> &[CodeUnit] {
        let scope = AnalyzerQueryScope::new(self);
        let token = scope.token();
        CSharpAnalyzer::global_static_using_types(self, token)
    }

    fn usage_global_static_using_types(&self) -> &[CodeUnit] {
        let scope = AnalyzerQueryScope::new(self);
        let token = scope.token();
        CSharpAnalyzer::usage_global_static_using_types(self, token)
    }

    fn global_using_namespaces(&self) -> &HashSet<String> {
        let scope = AnalyzerQueryScope::new(self);
        let token = scope.token();
        CSharpAnalyzer::global_using_namespaces(self, token)
    }

    fn file_using_namespaces_of(&self, token: QueryToken<'_>, file: &ProjectFile) -> Vec<String> {
        if let Some(cached) = self.memo_caches.file_using_namespaces.get(file) {
            return (*cached).clone();
        }
        let namespaces = graph_support::file_using_namespaces(self, token, file);
        self.memo_caches
            .file_using_namespaces
            .insert(file.clone(), Arc::new(namespaces.clone()));
        namespaces
    }

    fn sorted_global_using_namespaces(&self) -> Vec<String> {
        self.memo_caches
            .sorted_global_using_namespaces
            .get_or_init(|| {
                let mut namespaces: Vec<_> = CSharpSource::global_using_namespaces(self)
                    .iter()
                    .cloned()
                    .collect();
                namespaces.sort();
                namespaces
            })
            .clone()
    }

    fn global_using_namespaces_limited(
        &self,
        limit: usize,
        continue_query: &mut dyn FnMut() -> bool,
    ) -> LimitedQueryRows<String> {
        CSharpAnalyzer::global_using_namespaces_limited(self, limit, continue_query)
    }

    fn global_using_aliases(&self) -> &HashMap<String, String> {
        let scope = AnalyzerQueryScope::new(self);
        let token = scope.token();
        CSharpAnalyzer::global_using_aliases(self, token)
    }

    fn global_using_aliases_limited(
        &self,
        limit: usize,
        continue_query: &mut dyn FnMut() -> bool,
    ) -> LimitedQueryRows<(String, String)> {
        CSharpAnalyzer::global_using_aliases_limited(self, limit, continue_query)
    }
}

impl CSharpAnalyzer {
    pub(crate) fn signature_metadata_limited(
        &self,
        code_unit: &CodeUnit,
        limit: usize,
    ) -> crate::analyzer::store::LimitedQueryRows<SignatureMetadata> {
        self.inner.signature_metadata_limited(code_unit, limit)
    }

    pub(crate) fn signatures_limited(
        &self,
        code_unit: &CodeUnit,
        limit: usize,
    ) -> crate::analyzer::store::LimitedQueryRows<String> {
        self.inner.signatures_limited(code_unit, limit)
    }

    pub(crate) fn ranges_limited(
        &self,
        code_unit: &CodeUnit,
        limit: usize,
    ) -> crate::analyzer::store::LimitedQueryRows<crate::analyzer::Range> {
        self.inner.ranges_limited(code_unit, limit)
    }

    pub(crate) fn raw_supertypes_limited(
        &self,
        code_unit: &CodeUnit,
        limit: usize,
    ) -> crate::analyzer::store::LimitedQueryRows<String> {
        self.inner.raw_supertypes_limited(code_unit, limit)
    }
}

impl TestDetectionProvider for CSharpAnalyzer {}

use crate::analyzer::CodeUnitIndex;

impl CodeUnitIndex for CSharpAnalyzer {
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

    fn definitions(&self, fq_name: &str) -> Box<dyn Iterator<Item = CodeUnit> + '_> {
        self.inner.definitions(fq_name)
    }

    fn direct_children(&self, code_unit: &CodeUnit) -> Vec<CodeUnit> {
        self.inner.direct_children(code_unit)
    }

    fn parent_of(&self, code_unit: &CodeUnit) -> Option<CodeUnit> {
        self.inner.structural_parent_of(code_unit)
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
        self.declaration_candidates_by_identifier(identifier)
    }
}

impl IAnalyzer for CSharpAnalyzer {
    crate::analyzer::i_analyzer::forward_relational_definition_batch!();

    crate::analyzer::i_analyzer::forward_file_identity_invalidation!();

    fn working_tree_identity(&self) -> Option<std::sync::Arc<crate::gitblob::WorkingTreeIdentity>> {
        self.inner.working_tree_identity()
    }

    /// Build the assembly-backed external declaration index off the request
    /// path.
    ///
    /// #1615 forbids a diagnostic request from reading assemblies or
    /// `project.assets.json`, so the proof-gated ladder peeks at this cell
    /// through [`Self::retained_external_index`] and calls an unbuilt one an
    /// unknown boundary. This is the hook that fills it: `IndexWarmer` runs it
    /// on a background thread for the generation, and the once-lock makes it
    /// idempotent.
    fn warm_query_indexes(&self) {
        self.external_declaration_index();
    }

    fn query_indexes_warm(&self) -> bool {
        self.external_index.get().is_some()
    }

    fn semantic_diagnostics(
        &self,
        file: &ProjectFile,
        source: &str,
    ) -> crate::analyzer::SemanticDiagnosticReport {
        let scope = AnalyzerQueryScope::new(self);
        diagnostics::collect_csharp_semantic_diagnostics(self, scope.token(), file, source)
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

    fn partial_declaration_parts(&self, code_unit: &CodeUnit) -> Option<Vec<CodeUnit>> {
        if !code_unit.is_class() {
            return None;
        }
        Some(graph_support::partial_type_parts(self, code_unit))
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
        let compilation_digest = self.compilation_index().config_digest()?;
        let mut hasher = crate::analyzer::canonical_hash::CanonicalHasher::new(
            b"bifrost-csharp-content-with-compilation-config:v1",
        );
        hasher.field("sources", self.inner.language_content_identity().as_bytes());
        hasher.field("compilation_config", compilation_digest.as_bytes());
        Some(
            crate::analyzer::content_identity::WorkspaceContentIdentities::new([(
                Language::CSharp,
                crate::analyzer::semantic::ids::StableDigest::from_array(hasher.finish()),
            )]),
        )
    }

    fn workspace_fact_indexes(
        &self,
    ) -> Vec<&dyn crate::analyzer::read_verification::WorkspaceFactIndex> {
        self.inner.workspace_fact_indexes()
    }

    fn import_statements(&self, file: &ProjectFile) -> Vec<String> {
        self.inner.import_statements(file)
    }

    fn compute_cognitive_complexities(&self, file: &ProjectFile) -> Vec<(CodeUnit, u32)> {
        self.inner.compute_cognitive_complexities(file)
    }

    fn update(&self, changed_files: &BTreeSet<ProjectFile>) -> Self {
        let external_index = if changed_files
            .iter()
            .any(dependency_discovery::is_csharp_dependency_input)
        {
            Arc::new(std::sync::OnceLock::new())
        } else {
            self.external_index.clone()
        };
        Self {
            inner: self.inner.update(changed_files),
            memo_caches: Arc::new(CSharpMemoCaches::new(self.memo_caches.budget_bytes())),
            csharp_config: self.csharp_config.clone(),
            external_index,
        }
    }

    fn update_all(&self) -> Self {
        Self {
            inner: self.inner.update_all(),
            memo_caches: Arc::new(CSharpMemoCaches::new(self.memo_caches.budget_bytes())),
            csharp_config: self.csharp_config.clone(),
            external_index: Arc::new(std::sync::OnceLock::new()),
        }
    }

    fn parse_errors(&self, file: &ProjectFile) -> Option<Vec<crate::analyzer::ParseError>> {
        self.inner.parse_errors(file)
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

    fn contains_tests(&self, file: &ProjectFile) -> bool {
        self.inner.contains_tests(file) || self.hierarchy_test_files().contains(file)
    }

    fn in_test_region(&self, code_unit: &crate::analyzer::CodeUnit) -> bool {
        self.inner.in_test_region(code_unit)
    }

    fn find_test_assertion_smells(
        &self,
        file: &ProjectFile,
        weights: TestAssertionWeights,
    ) -> Vec<TestAssertionSmell> {
        if !self.contains_tests(file) || file_language(file) != Language::CSharp {
            return Vec::new();
        }
        let Ok(source) = self.inner.project().read_source(file) else {
            return Vec::new();
        };
        detect_csharp_test_assertion_smells(file, &source, &weights)
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
            .filter(|file| file_language(file) == Language::CSharp)
            .cloned()
            .collect();
        if requested_files.is_empty() {
            return Vec::new();
        }

        let corpus_units =
            crate::analyzer::clone_detection::clone_corpus_function_units(self, Language::CSharp);
        let _query_scope = crate::analyzer::AnalyzerQueryScope::new(self);
        let all_candidates: Vec<CloneCandidateProfile> = corpus_units
            .iter()
            .filter_map(|code_unit| build_csharp_clone_candidate_data(self, code_unit, weights))
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

    fn import_analysis_provider(&self) -> Option<&dyn ImportAnalysisProvider> {
        Some(self)
    }

    fn type_hierarchy_provider(&self) -> Option<&dyn TypeHierarchyProvider> {
        Some(self)
    }
}

#[cfg(any(test, feature = "test-support"))]
impl crate::analyzer::AnalyzerTestHooks for CSharpAnalyzer {
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

    fn reset_package_declaration_scan_count_for_test(&self) {
        self.inner
            .test_hooks()
            .reset_package_declaration_scan_count_for_test();
    }

    fn package_declaration_scan_count_for_test(&self) -> usize {
        self.inner
            .test_hooks()
            .package_declaration_scan_count_for_test()
    }

    fn reset_candidate_hydration_count_for_test(&self) {
        self.inner.reset_full_hydration_count_for_test();
    }

    fn candidate_hydration_count_for_test(&self) -> usize {
        self.inner.full_hydration_count_for_test() + self.inner.bulk_hydration_count_for_test()
    }
}

static CSHARP_USAGE_STRATEGY: CSharpUsageGraphStrategy = CSharpUsageGraphStrategy::new();

pub(crate) struct CSharpSupport;

impl LanguageSupport for CSharpSupport {
    fn language(&self) -> Language {
        Language::CSharp
    }

    fn display_symbol_name(&self, symbol: &str) -> String {
        csharp_normalize_full_name(symbol)
    }

    fn source_identifier<'s>(&self, identifier: &'s str) -> &'s str {
        strip_csharp_generic_arity(identifier)
    }

    fn alias_name_segment<'s>(&self, segment: &'s str) -> &'s str {
        strip_csharp_generic_arity(segment)
    }

    fn signature_metadata_limited(
        &self,
        analyzer: &dyn IAnalyzer,
        unit: &CodeUnit,
        limit: usize,
    ) -> Option<LimitedQueryRows<SignatureMetadata>> {
        resolve_analyzer::<CSharpAnalyzer>(analyzer)
            .map(|csharp| csharp.signature_metadata_limited(unit, limit))
    }

    fn signatures_limited(
        &self,
        analyzer: &dyn IAnalyzer,
        unit: &CodeUnit,
        limit: usize,
    ) -> Option<LimitedQueryRows<String>> {
        resolve_analyzer::<CSharpAnalyzer>(analyzer)
            .map(|csharp| csharp.signatures_limited(unit, limit))
    }

    fn declaration_ranges_limited(
        &self,
        analyzer: &dyn IAnalyzer,
        unit: &CodeUnit,
        limit: usize,
    ) -> Option<LimitedQueryRows<Range>> {
        resolve_analyzer::<CSharpAnalyzer>(analyzer)
            .map(|csharp| csharp.ranges_limited(unit, limit))
    }

    fn forward_query_provider<'a>(
        &self,
        analyzer: &'a dyn IAnalyzer,
    ) -> Option<&'a dyn ForwardQueryProvider> {
        resolve_analyzer::<CSharpAnalyzer>(analyzer).map(|value| value as _)
    }

    fn ecosystem(&self) -> UsageEcosystem {
        UsageEcosystem::CSharp
    }

    fn reference_plugin(&self) -> crate::analyzer::languages::ReferenceLanguagePlugin {
        crate::analyzer::languages::ReferenceLanguagePlugin::new(
            &CSHARP_USAGE_STRATEGY,
            &CSharpEdgePass,
        )
    }

    fn dead_code(&self) -> DeadCodeSupport {
        DeadCodeSupport {
            strategy: Some(&CSHARP_USAGE_STRATEGY),
            bulk: Some(&CSharpDeadCodeBulk),
        }
    }

    fn structural_receiver(&self) -> Option<&'static dyn StructuralReceiverResolver> {
        Some(&CSharpSupport)
    }

    fn parser_language(&self, _flavor: crate::analyzer::ParserFlavor) -> tree_sitter::Language {
        tree_sitter_c_sharp::LANGUAGE.into()
    }

    fn structural_spec(&self) -> &'static dyn crate::analyzer::structural::StructuralSpec {
        &brokk_bifrost_csharp::structural::CSHARP_STRUCTURAL_SPEC
    }

    fn highlight_query(&self) -> Option<&'static str> {
        Some(tree_sitter_c_sharp::HIGHLIGHTS_QUERY)
    }
}

struct CSharpEdgePass;

impl LanguageEdgePass for CSharpEdgePass {
    fn id(&self) -> EdgePassId {
        EdgePassId::CSharp
    }

    fn edge_sites(&self, ctx: &EdgeSiteScanCtx<'_>) -> Option<LanguageEdgeSites> {
        let scope = AnalyzerQueryScope::new(ctx.analyzer);
        let token = scope.token();
        build_rooted_csharp_usage_edges(ctx.analyzer, token, ctx.fqns, ctx.keep_file)
            .map(LanguageEdgeSites::Fqn)
    }

    fn edge_weights(&self, ctx: &EdgeWeightScanCtx<'_>) -> Option<LanguageEdgeWeights> {
        let scope = AnalyzerQueryScope::new(ctx.analyzer);
        let token = scope.token();
        build_csharp_usage_edge_weights(ctx.analyzer, token, ctx.fqns, ctx.keep_file)
            .map(LanguageEdgeWeights::Fqn)
    }
}

impl StructuralReceiverResolver for CSharpSupport {
    fn resolve_type_bounded(
        &self,
        query: BoundedReceiverQuery<'_>,
    ) -> BoundedResolution<TypeLookupOutcome> {
        let scope = AnalyzerQueryScope::new(query.analyzer);
        let token = scope.token();
        resolve_csharp_type_bounded(
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
        let scope = AnalyzerQueryScope::new(query.analyzer);
        let token = scope.token();
        resolve_csharp_bounded(
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
}

#[derive(Default)]
struct CSharpDeadCodeMemo {
    file_count: Option<usize>,
    overloaded_fqns: HashMap<String, bool>,
    unsafe_using_member_forms_present: Option<bool>,
}

struct CSharpDeadCodeBulk;

impl DeadCodeBulkProof for CSharpDeadCodeBulk {
    fn id(&self) -> EdgePassId {
        EdgePassId::CSharp
    }

    fn new_memo(&self) -> Box<dyn std::any::Any + Send> {
        Box::new(CSharpDeadCodeMemo::default())
    }

    /// Tested inline rather than through a `dead_code_bulk_eligibility` in the graph
    /// module, because what disqualifies a C# candidate is local to the candidate:
    /// fields, constructors, overloaded functions, and any workspace using an unsafe
    /// `using` member form.
    fn needs_precise_scan(&self, routing: DeadCodeRouting<'_>) -> bool {
        let DeadCodeRouting {
            analyzer,
            candidate,
            file_cap,
            memo,
        } = routing;
        let CSharpDeadCodeMemo {
            file_count,
            overloaded_fqns,
            unsafe_using_member_forms_present,
        } = memo.downcast_mut().expect("C# bulk memo");
        if *file_count.get_or_insert_with(|| analyzable_file_count(analyzer, Language::CSharp))
            > file_cap
        {
            return true;
        }
        if candidate.is_field() || csharp_constructor_candidate(analyzer, candidate) {
            return true;
        }

        let overloaded = if candidate.is_function() {
            let fqn = candidate.fq_name();
            *overloaded_fqns.entry(fqn.clone()).or_insert_with(|| {
                fqn_has_multiple_function_definitions(analyzer, Language::CSharp, &fqn)
            })
        } else {
            false
        };
        let has_unsafe_using_member_forms = candidate.is_function()
            && *unsafe_using_member_forms_present
                .get_or_insert_with(|| csharp_unsafe_using_member_forms_present(analyzer));

        candidate.is_function() && (overloaded || has_unsafe_using_member_forms)
    }

    fn preflight(&self, analyzer: &dyn IAnalyzer) -> DeadCodeBulkPreflight {
        DeadCodeBulkPreflight::Ready {
            label: "C#",
            files: analyzable_file_count(analyzer, Language::CSharp),
        }
    }

    fn build(
        &self,
        analyzer: &dyn IAnalyzer,
        candidates: &[CodeUnit],
    ) -> Option<DeadCodeBulkEdges> {
        let csharp = resolve_analyzer::<CSharpAnalyzer>(analyzer)?;
        let callees = candidate_fqns(candidates);
        cached_dead_code_usage_edges(
            analyzer,
            &csharp.memo_caches.dead_code_usage_edges,
            &callees,
            |token| build_inbound_csharp_usage_edges_with_completeness(analyzer, token, &callees),
        )
        .map(DeadCodeBulkEdges::Fqn)
    }
}

#[cfg(test)]
mod dead_code_cache_tests {
    use super::*;
    use crate::analyzer::usages::inverted_edges::UsageEdges;
    use crate::inline_project::InlineTestProject;

    #[test]
    fn update_all_update_and_overlay_clone_start_with_empty_dead_code_caches() {
        let fixture = InlineTestProject::with_language(Language::CSharp)
            .file("A.cs", "class A {}")
            .build();
        let analyzer = CSharpAnalyzer::from_project(fixture.project().clone());
        let key: Arc<[String]> = vec!["A".to_string()].into();
        analyzer
            .memo_caches
            .dead_code_usage_edges
            .insert(key.clone(), Arc::new(UsageEdges::default()));

        let updated = analyzer.update(&std::collections::BTreeSet::new());
        assert!(
            updated
                .memo_caches
                .dead_code_usage_edges
                .get(&key)
                .is_none()
        );
        let rebuilt = analyzer.update_all();
        assert!(
            rebuilt
                .memo_caches
                .dead_code_usage_edges
                .get(&key)
                .is_none()
        );
        let overlay = analyzer.clone_with_project(fixture.project_dyn());
        assert!(
            overlay
                .memo_caches
                .dead_code_usage_edges
                .get(&key)
                .is_none()
        );
    }
}

#[cfg(test)]
mod package_inventory_gate_tests {
    use super::*;
    use crate::analyzer::OverlayProject;
    use crate::inline_project::InlineTestProject;

    #[test]
    fn incomplete_package_inventory_cannot_suppress_an_exact_csharp_fqn() {
        let fixture = InlineTestProject::with_language(Language::CSharp)
            .file(
                "Shared/Widget.cs",
                "namespace Shared { public class Widget { } }",
            )
            .file(
                "Consumer.cs",
                "using Shared; public class Consumer { private Widget value; }",
            )
            .file(
                "Other/Marker.cs",
                "namespace Other { public class Marker { } }",
            )
            .build();
        let analyzer = CSharpAnalyzer::from_project(fixture.project().clone());

        assert!(analyzer.inner.workspace_package_inventory_complete());
        assert_eq!(
            analyzer.inner.try_persisted_package_may_exist("Shared"),
            Some(true),
            "a persisted package witness remains immediately authoritative"
        );

        analyzer
            .inner
            .delete_workspace_package_membership_for_test("Shared");
        assert_eq!(
            analyzer.inner.try_persisted_package_may_exist("Shared"),
            Some(false),
            "a complete package inventory may publish an exact negative"
        );

        let overlay = Arc::new(OverlayProject::new(fixture.project_dyn()));
        let marker = fixture.file("Other/Marker.cs");
        assert!(overlay.set(
            marker.abs_path(),
            "namespace Other { public class EditedMarker { } }".to_string(),
        ));
        let overlay_project: Arc<dyn Project> = Arc::new(overlay.snapshot());
        let request = analyzer.clone_with_project(overlay_project);
        assert!(!request.inner.workspace_package_inventory_complete());
        assert_eq!(
            request.inner.try_persisted_package_may_exist("Shared"),
            Some(true),
            "an absent partial package projection must conservatively preserve the exact probe"
        );

        request.reset_visible_type_store_build_counts_for_test();
        let consumer = fixture.file("Consumer.cs");
        let resolve = || {
            let scope = AnalyzerQueryScope::new(&request);
            graph_support::visible_type_candidates(&request, scope.token(), &consumer, "Widget")
        };
        let candidates = resolve();
        assert_eq!(
            candidates.iter().map(CodeUnit::fq_name).collect::<Vec<_>>(),
            vec!["Shared.Widget"],
            "C# must perform the exact structured FQN probe when package absence is uncertain"
        );
        assert_eq!(
            resolve(),
            candidates,
            "a warm repeat must preserve the exact C# answer"
        );
        assert_eq!(
            request.visible_type_store_build_counts_for_test(),
            (1, 1),
            "the conservative package answer and exact FQN result must each cache after one computation"
        );

        assert!(overlay.set(
            marker.abs_path(),
            "namespace Shared { public class DirtyMarker { } }".to_string(),
        ));
        let dirty_project: Arc<dyn Project> = Arc::new(overlay.snapshot());
        let dirty = analyzer.clone_with_project(dirty_project);
        assert_eq!(
            dirty.inner.try_persisted_package_may_exist("Shared"),
            Some(true),
            "a dirty structured declaration is positive evidence even when persistence misses"
        );
    }
}
