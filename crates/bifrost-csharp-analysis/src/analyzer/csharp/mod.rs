//! The analyzer-owned shim over [`brokk_bifrost_csharp`].
//!
//! What lives here is everything the language crate cannot name: the
//! [`CSharpAnalyzer`] newtype and its generation-owned bounded caches and lazy
//! cells; the accessors that implement
//! [`graph_support::CSharpSource`] out of them; the `CSharpAdapter`
//! forwarding shell; the `IAnalyzer`/`CodeUnitIndex` impls; and the
//! `LanguageSupport` SPI block.

use brokk_bifrost_analysis::{
    delegate_inner_methods, delegate_inner_procedure_fact_methods,
    forward_file_identity_invalidation, forward_relational_definition_batch,
    impl_forward_query_provider,
};

#[cfg(any(test, feature = "test-support"))]
use brokk_bifrost_analysis::delegate_inner_test_hook_methods;

#[doc(hidden)]
pub mod adapter;
mod cache;
mod call_conversion;
mod catch_facts;
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

use brokk_bifrost_core::analyzer::model::Range;

use brokk_bifrost_core::analyzer::query_token::QueryToken;
use brokk_bifrost_core::analyzer::structural::resolution::BoundaryStatus;

// The language halves of the type-resolution and hierarchy logic moved to
// `brokk-bifrost-csharp`; re-exporting the modules keeps every
// `crate::analyzer::csharp::{graph_support,hierarchy}::` call site in the
// definition route, the type route and the usage graph pointing at the same
// paths.
pub(crate) use brokk_bifrost_csharp::graph_support;

// C# language knowledge lives in `brokk-bifrost-csharp`; these keep their
// historical `crate::analyzer::csharp::` paths for the analysis-side consumers
// (the re-export hub in `analyzer/mod.rs`, the definition and type routes, the
// usage graph, and this crate's own C# modules).
use brokk_bifrost_csharp::syntax::csharp_normalize_full_name;
pub use brokk_bifrost_csharp::syntax::{csharp_source_name_segment, strip_csharp_generic_arity};

use brokk_bifrost_analysis::analyzer::clone_detection::detect_language_structural_clone_smells;

use brokk_bifrost_analysis::analyzer::common::limited_known_rows;

use brokk_bifrost_analysis::analyzer::languages::BoundedReceiverQuery;

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

use brokk_bifrost_analysis::analyzer::languages::fqn_has_multiple_function_definitions;

use brokk_bifrost_analysis::analyzer::languages::ready_preflight;

use brokk_bifrost_core::analyzer::query_batch::LimitedQueryRows;

use crate::analyzer::usages::csharp_graph::CSharpUsageGraphStrategy;

use crate::analyzer::usages::csharp_graph::build_csharp_usage_edge_weights;

use crate::analyzer::usages::csharp_graph::build_inbound_csharp_usage_edges_with_completeness;

use crate::analyzer::usages::csharp_graph::build_rooted_csharp_usage_edges;

use brokk_bifrost_core::analyzer::usages::resolution_session::BoundedResolution;

use brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionLookupOutcome;

use crate::analyzer::usages::get_definition::csharp::resolve_csharp_bounded;

use brokk_bifrost_analysis::analyzer::usages::get_type::TypeLookupOutcome;

use crate::analyzer::usages::get_type::resolve_csharp_type_bounded;

use brokk_bifrost_analysis::analyzer::usages::receiver_sites::ReceiverSiteInputMode;

use brokk_bifrost_analysis::analyzer::usages::workspace_graph::UsageEcosystem;

use brokk_bifrost_core::analyzer::config::AnalyzerConfig;

use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::AnalyzerStoreContext;

use brokk_bifrost_core::analyzer::definition_lookup::BoundedDefinitionLookup;

use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::BuildProgress;

use brokk_bifrost_core::analyzer::config::CSharpAnalyzerConfig;

use brokk_bifrost_core::analyzer::model::CodeUnit;

use brokk_bifrost_analysis::analyzer::analyzer_definition_lookup::ForwardQueryProvider;

use brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer;

use brokk_bifrost_core::analyzer::capabilities::ImportAnalysisProvider;

use brokk_bifrost_core::analyzer::model::Language;

use brokk_bifrost_core::analyzer::project::Project;

use brokk_bifrost_core::analyzer::model::ProjectFile;

use brokk_bifrost_core::analyzer::model::SignatureMetadata;

use brokk_bifrost_core::analyzer::model::TestAssertionSmell;

use brokk_bifrost_core::analyzer::model::TestAssertionWeights;

use brokk_bifrost_core::analyzer::capabilities::TestDetectionProvider;

use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::TreeSitterAnalyzer;

use brokk_bifrost_core::analyzer::capabilities::TypeHierarchyProvider;

use brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer;

use brokk_bifrost_core::hash::HashMap;

use brokk_bifrost_core::hash::HashSet;

use brokk_bifrost_core::analyzer::model::CloneSmell;

use brokk_bifrost_core::analyzer::model::CloneSmellWeights;
use moka::sync::Cache;
use std::collections::BTreeSet;
use std::sync::Arc;

use brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope;

use brokk_bifrost_core::analyzer::query_token::QueryScope;

#[doc(hidden)]
pub use crate::analyzer::csharp::adapter::CSharpAdapter;
use brokk_bifrost_csharp::dead_code::{
    csharp_constructor_candidate, csharp_unsafe_using_member_forms_present,
};
use brokk_bifrost_csharp::test_detection::detect_csharp_test_assertion_smells;

use crate::analyzer::csharp::cache::CSharpMemoCaches;

use crate::analyzer::csharp::cache::PersistedFqnLookup;

use crate::analyzer::csharp::clones::build_csharp_clone_candidate_data;

use crate::analyzer::csharp::external::CSharpExternalDeclarationIndex;

use crate::analyzer::csharp::external::CSharpExternalDeclarations;

use crate::analyzer::csharp::external::CSharpExternalMember;

use crate::analyzer::csharp::external::CSharpExternalType;

use brokk_bifrost_csharp::graph_support::CSharpSource;

pub use crate::analyzer::csharp::catch_facts::CSharpCatchFacts;

pub use crate::analyzer::csharp::catch_facts::CSharpCatchTypeRelation;

pub use crate::analyzer::csharp::catch_facts::csharp_catch_facts;

pub(crate) use crate::analyzer::csharp::dependency_discovery::is_csharp_dependency_input;

pub(crate) use crate::analyzer::csharp::dependency_discovery::is_csharp_dependency_input_path;

fn cached_file_value<T: Clone + Send + Sync + 'static>(
    cache: &Cache<ProjectFile, Arc<T>>,
    file: &ProjectFile,
    compute: impl FnOnce() -> T,
) -> T {
    if let Some(cached) = cache.get(file) {
        return (*cached).clone();
    }
    let value = compute();
    cache.insert(file.clone(), Arc::new(value.clone()));
    value
}

fn cached_limited_query_rows<T>(
    cached: impl FnOnce() -> Option<LimitedQueryRows<T>>,
    compute: impl FnOnce() -> LimitedQueryRows<T>,
    cache_complete: impl FnOnce(&[T]),
) -> LimitedQueryRows<T> {
    if let Some(rows) = cached() {
        return rows;
    }
    let batch = compute();
    if batch.complete {
        cache_complete(&batch.rows);
    }
    batch
}

#[derive(Clone)]
pub struct CSharpAnalyzer {
    inner: TreeSitterAnalyzer<CSharpAdapter>,
    memo_caches: Arc<CSharpMemoCaches>,
    csharp_config: CSharpAnalyzerConfig,
    external_index: Arc<std::sync::OnceLock<CSharpExternalDeclarationIndex>>,
}

impl_forward_query_provider!(CSharpAnalyzer);

impl CSharpAnalyzer {
    pub(crate) fn update_all_with_progress(
        &self,
        progress: Option<brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::BuildProgress>,
    ) -> Self {
        Self {
            inner: self.inner.update_all_with_progress(progress),
            memo_caches: Arc::new(CSharpMemoCaches::new(self.memo_caches.budget_bytes())),
            csharp_config: self.csharp_config.clone(),
            external_index: Arc::new(std::sync::OnceLock::new()),
        }
    }

    pub(crate) fn clone_with_project(&self, project: Arc<dyn Project>) -> Self {
        let mut clone = self.clone_for_index_warm(project);
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
    ) -> Result<Self, brokk_bifrost_analysis::analyzer::store::StoreError> {
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

    delegate_inner_methods! {
        #[doc(hidden)]
        pub fn reset_full_hydration_count_for_test(&self);
    }

    delegate_inner_methods! {
        #[doc(hidden)]
        pub fn full_hydration_count_for_test(&self) -> usize;
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
        cached_file_value(&self.memo_caches.namespace_by_file, file, || {
            graph_support::compute_namespace_of_file(self, file)
        })
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
            return limited_known_rows(1, std::iter::once((*cached).clone()), limit);
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

    /// The external declaration surface C# resolution reads: this analyzer's
    /// assembly-backed index plus the declaration facts the activated semantic
    /// packs publish (#3461).
    pub(crate) fn external_declarations(
        &self,
        packs: Option<
            Arc<brokk_bifrost_analysis::analyzer::semantic_model::overlay::SemanticModelOverlay>,
        >,
    ) -> CSharpExternalDeclarations<'_> {
        CSharpExternalDeclarations::new(self.external_declaration_index(), packs)
    }

    /// The canonical external identity a C# member call names, or `None` when
    /// the external declaration surface decides no single one (#3461).
    ///
    /// `candidate_owners` is what the C# receiver ladder already produced for
    /// the call: the receiver's written type plus the expansion of every
    /// `using` namespace in scope, which is the same tier walk a type spelling
    /// takes. Only a candidate the external surface actually declares -- and
    /// that declares the member -- can answer, so a bogus expansion such as
    /// `System.Threading.Tasks.HttpClient` drops out on evidence rather than on
    /// spelling. More than one surviving owner is honest ambiguity, not a
    /// choice to make, so it publishes nothing. The owners are compared as the
    /// identities the surface keyed on, so two spellings of one declaration are
    /// one answer rather than an ambiguity.
    ///
    /// The returned identity is `<owner FQN>.<member>` -- the canonical
    /// publication Java adopted in #3466 -- not the receiver *variable*
    /// spelling the reference site wrote. That is what lets a reviewed summary
    /// bind the exact member without any name matching.
    pub(crate) fn external_member_identity(
        &self,
        packs: Option<
            Arc<brokk_bifrost_analysis::analyzer::semantic_model::overlay::SemanticModelOverlay>,
        >,
        candidate_owners: &[String],
        member: &str,
    ) -> Option<String> {
        if member.is_empty() {
            return None;
        }
        let external = self.external_declarations(packs);
        if external.is_empty() {
            return None;
        }
        let mut owners = candidate_owners
            .iter()
            .filter_map(|owner| external.declaring_owner(owner, member))
            .collect::<Vec<_>>();
        owners.sort();
        owners.dedup();
        let [owner] = owners.as_slice() else {
            return None;
        };
        Some(format!("{owner}.{member}"))
    }

    /// The canonical external identity of one applicable C# constructor, or
    /// `None` when the owner ladder remains empty, ambiguous, or lacks an
    /// exact declaration at this arity.
    pub(crate) fn external_constructor_identity(
        &self,
        packs: Option<
            Arc<brokk_bifrost_analysis::analyzer::semantic_model::overlay::SemanticModelOverlay>,
        >,
        candidate_owners: &[String],
        parameter_count: u32,
    ) -> Option<(String, String)> {
        let external = self.external_declarations(packs);
        if external.is_empty() {
            return None;
        }
        let mut targets = candidate_owners
            .iter()
            .filter_map(|owner| external.constructor(owner, parameter_count))
            .collect::<Vec<_>>();
        targets.sort();
        targets.dedup();
        let [target] = targets.as_slice() else {
            return None;
        };
        Some(target.clone())
    }

    /// Whether the exact external C# member identity is static, using the
    /// same activated declaration surface that published the identity.
    pub(crate) fn external_member_is_static(
        &self,
        packs: Option<
            Arc<brokk_bifrost_analysis::analyzer::semantic_model::overlay::SemanticModelOverlay>,
        >,
        owner: &str,
        member: &str,
    ) -> Option<bool> {
        self.external_declarations(packs)
            .member_is_static(owner, member)
    }

    /// Whether the exact external C# type identity is sealed according to the
    /// active declaration surface.
    pub(crate) fn external_type_is_sealed(
        &self,
        packs: Option<
            Arc<brokk_bifrost_analysis::analyzer::semantic_model::overlay::SemanticModelOverlay>,
        >,
        owner: &str,
    ) -> Option<bool> {
        self.external_declarations(packs).type_is_sealed(owner)
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
            return limited_known_rows(cached.len(), cached.iter().cloned(), limit);
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
        let cache = &self.memo_caches.using_aliases;
        cached_limited_query_rows(
            || {
                cache.get(file).map(|cached| {
                    limited_known_rows(
                        cached.len(),
                        cached
                            .iter()
                            .map(|(alias, target)| (alias.clone(), target.clone())),
                        limit,
                    )
                })
            },
            || {
                graph_support::compute_using_aliases_of_limited(
                    self,
                    token,
                    file,
                    limit,
                    &mut continue_query,
                )
            },
            |rows| {
                cache.insert(file.clone(), Arc::new(rows.iter().cloned().collect()));
            },
        )
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
        let cache = &self.memo_caches.global_using_namespaces;
        cached_limited_query_rows(
            || {
                cache
                    .get()
                    .map(|cached| limited_known_rows(cached.len(), cached.iter().cloned(), limit))
            },
            || {
                graph_support::compute_global_using_namespaces_limited(
                    self,
                    limit,
                    &mut continue_query,
                )
            },
            |rows| {
                cache.get_or_init(|| rows.iter().cloned().collect());
            },
        )
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
        let cache = &self.memo_caches.global_using_aliases;
        cached_limited_query_rows(
            || {
                cache.get().map(|cached| {
                    limited_known_rows(
                        cached.len(),
                        cached
                            .iter()
                            .map(|(alias, target)| (alias.clone(), target.clone())),
                        limit,
                    )
                })
            },
            || {
                graph_support::compute_global_using_aliases_limited(
                    self,
                    limit,
                    &mut continue_query,
                )
            },
            |rows| {
                cache.get_or_init(|| rows.iter().cloned().collect());
            },
        )
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
            return limited_known_rows(cached.len(), cached.iter().cloned(), limit);
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
        brokk_bifrost_analysis::analyzer::with_analyzer_usage_definitions(
            self,
            Language::CSharp,
            read,
        );
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
    ) -> LimitedQueryRows<brokk_bifrost_core::analyzer::model::ImportInfo> {
        self.inner.import_info_of_limited(token, file, limit)
    }

    fn workspace_import_info_limited(
        &self,
        limit: usize,
        continue_query: &mut dyn FnMut() -> bool,
    ) -> LimitedQueryRows<brokk_bifrost_core::analyzer::model::ImportInfo> {
        let scope = AnalyzerQueryScope::new(self);
        let token = scope.token();
        self.inner
            .workspace_import_info_limited(token, limit, continue_query)
    }

    delegate_inner_methods! {
        fn raw_supertypes_of(&self, code_unit: &CodeUnit) -> Vec<String>;
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
        cached_file_value(&self.memo_caches.file_using_namespaces, file, || {
            graph_support::file_using_namespaces(self, token, file)
        })
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
    delegate_inner_methods! {
        #[doc(hidden)]
        pub fn signature_metadata_limited(
        &self,
        code_unit: &CodeUnit,
        limit: usize,
    ) -> brokk_bifrost_core::analyzer::query_batch::LimitedQueryRows<SignatureMetadata>;
    }

    pub(crate) fn signatures_limited(
        &self,
        code_unit: &CodeUnit,
        limit: usize,
    ) -> brokk_bifrost_core::analyzer::query_batch::LimitedQueryRows<String> {
        self.inner.signatures_limited(code_unit, limit)
    }

    #[doc(hidden)]
    pub fn ranges_limited(
        &self,
        code_unit: &CodeUnit,
        limit: usize,
    ) -> brokk_bifrost_core::analyzer::query_batch::LimitedQueryRows<
        brokk_bifrost_core::analyzer::model::Range,
    > {
        self.inner.ranges_limited(code_unit, limit)
    }

    delegate_inner_methods! {
        pub(crate) fn raw_supertypes_limited(
        &self,
        code_unit: &CodeUnit,
        limit: usize,
    ) -> brokk_bifrost_core::analyzer::query_batch::LimitedQueryRows<String>;
    }
}

impl TestDetectionProvider for CSharpAnalyzer {}

use brokk_bifrost_core::analyzer::code_unit_index::CodeUnitIndex;

impl CodeUnitIndex for CSharpAnalyzer {
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

    fn parent_of(&self, code_unit: &CodeUnit) -> Option<CodeUnit> {
        self.inner.structural_parent_of(code_unit)
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
        self.inner.get_skeleton(code_unit)
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
        self.declaration_candidates_by_identifier(identifier)
    }
}

impl IAnalyzer for CSharpAnalyzer {
    delegate_inner_procedure_fact_methods!();

    forward_relational_definition_batch!();

    forward_file_identity_invalidation!();

    fn working_tree_identity(
        &self,
    ) -> Option<std::sync::Arc<brokk_bifrost_core::gitblob::WorkingTreeIdentity>> {
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
    ) -> brokk_bifrost_core::analyzer::model::SemanticDiagnosticReport {
        let scope = AnalyzerQueryScope::new(self);
        diagnostics::collect_csharp_semantic_diagnostics(self, scope.token(), file, source)
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

    fn partial_declaration_parts(&self, code_unit: &CodeUnit) -> Option<Vec<CodeUnit>> {
        if !code_unit.is_class() {
            return None;
        }
        Some(graph_support::partial_type_parts(self, code_unit))
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

    fn workspace_content_identities(
        &self,
    ) -> Option<brokk_bifrost_analysis::analyzer::content_identity::WorkspaceContentIdentities>
    {
        let compilation_digest = self.compilation_index().config_digest()?;
        let mut hasher = brokk_bifrost_core::analyzer::canonical_hash::CanonicalHasher::new(
            b"bifrost-csharp-content-with-compilation-config:v1",
        );
        hasher.field("sources", self.inner.language_content_identity().as_bytes());
        hasher.field("compilation_config", compilation_digest.as_bytes());
        Some(
            brokk_bifrost_analysis::analyzer::content_identity::WorkspaceContentIdentities::new([
                (
                    Language::CSharp,
                    brokk_bifrost_semantic::analyzer::semantic::ids::StableDigest::from_array(
                        hasher.finish(),
                    ),
                ),
            ]),
        )
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
        let external_index = brokk_bifrost_analysis::analyzer::updated_external_index(
            &self.external_index,
            changed_files,
            dependency_discovery::is_csharp_dependency_input,
        );
        Self {
            inner: self.inner.update(changed_files),
            memo_caches: Arc::new(CSharpMemoCaches::new(self.memo_caches.budget_bytes())),
            csharp_config: self.csharp_config.clone(),
            external_index,
        }
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

    fn contains_tests(&self, file: &ProjectFile) -> bool {
        self.inner.contains_tests(file) || self.hierarchy_test_files().contains(file)
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
            Language::CSharp,
            |source| detect_csharp_test_assertion_smells(file, source, &weights),
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
            Language::CSharp,
            |code_unit| build_csharp_clone_candidate_data(self, code_unit, weights),
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

    fn member_family_provider(
        &self,
    ) -> Option<&dyn brokk_bifrost_analysis::analyzer::usages::member_family::MemberFamilyProvider>
    {
        Some(self)
    }
}

/// C# joins the #1721 nominal-family rollout.
///
/// The relation the shared walk uses is C#'s own: an interface member is
/// implemented with no keyword, while a class member is overridden only when
/// the derived member writes `override` and the base member is `virtual`,
/// `abstract`, or itself an `override`. A member that writes `new` -- or
/// nothing, which is implicit `new` -- hides rather than overrides, and gets no
/// edge.
///
/// `self` is both the declaration source and the hierarchy source. Unlike Java,
/// no other realm can contribute an ancestor edge to a C# type, so the
/// multi-analyzer delegates here unchanged.
impl brokk_bifrost_analysis::analyzer::usages::member_family::MemberFamilyProvider
    for CSharpAnalyzer
{
    fn member_family_capability(
        &self,
        member: &CodeUnit,
    ) -> brokk_bifrost_core::analyzer::structural::resolution::MemberFamilyCapability {
        brokk_bifrost_analysis::analyzer::usages::member_family::csharp_member_family_capability(
            self, member,
        )
    }

    fn member_family(
        &self,
        member: &CodeUnit,
        cancellation: Option<&brokk_bifrost_core::cancellation::CancellationToken>,
    ) -> brokk_bifrost_analysis::analyzer::usages::member_family::MemberFamilyAnswer {
        brokk_bifrost_analysis::analyzer::usages::member_family::csharp_member_family(
            self,
            self,
            member,
            cancellation,
        )
    }
}

#[cfg(any(test, feature = "test-support"))]
impl brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerTestHooks for CSharpAnalyzer {
    delegate_inner_test_hook_methods! {
        fn reset_definition_candidates_query_count_for_test(&self);
    }

    delegate_inner_test_hook_methods! {
        fn definition_candidates_query_count_for_test(&self) -> usize;
    }

    delegate_inner_test_hook_methods! {
        fn reset_relational_definition_batch_call_count_for_test(&self);
    }

    delegate_inner_test_hook_methods! {
        fn relational_definition_batch_call_count_for_test(&self) -> usize;
    }

    delegate_inner_test_hook_methods! {
        fn reset_full_declaration_scan_count_for_test(&self);
    }

    delegate_inner_test_hook_methods! {
        fn full_declaration_scan_count_for_test(&self) -> usize;
    }

    delegate_inner_test_hook_methods! {
        fn reset_package_declaration_scan_count_for_test(&self);
    }

    delegate_inner_test_hook_methods! {
        fn package_declaration_scan_count_for_test(&self) -> usize;
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
}

static CSHARP_USAGE_STRATEGY: CSharpUsageGraphStrategy = CSharpUsageGraphStrategy::new();

#[doc(hidden)]
pub struct CSharpSupport;

impl LanguageSupport for CSharpSupport {
    fn workspace_semantic_diagnostics(
        &self,
        workspace: &brokk_bifrost_analysis::analyzer::multi_analyzer::MultiAnalyzer,
        token: brokk_bifrost_core::analyzer::query_token::QueryToken<'_>,
        file: &ProjectFile,
        source: &str,
    ) -> Option<brokk_bifrost_core::analyzer::model::SemanticDiagnosticReport> {
        // C# reads the retained dependency-discovery evidence that refines an
        // unindexed assembly boundary, and a host publishes that on the
        // analyzer it ran discovery against, which is this composite one.
        // Delegating to the `CSharpAnalyzer` would hand the collector no
        // evidence at all, so every miss past a `using` would report the
        // weakest boundary even where the build declares the assembly.
        Some(diagnostics::collect_csharp_semantic_diagnostics(
            workspace, token, file, source,
        ))
    }

    fn knowledge(
        &self,
    ) -> &'static dyn brokk_bifrost_core::analyzer::language_knowledge::LanguageKnowledge {
        &brokk_bifrost_csharp::CSharpKnowledge
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
                CSharpAnalyzer::new_with_config_store_context(
                    project,
                    config,
                    store_context,
                    progress,
                )?,
            ),
        )
    }

    fn is_configuration_input(&self, file: &ProjectFile) -> bool {
        crate::analyzer::csharp::is_csharp_dependency_input(file)
    }

    fn procedure_syntax_roles(
        &self,
    ) -> Option<brokk_bifrost_analysis::analyzer::languages::ProcedureSyntaxRoles> {
        Some(semantic::PROCEDURE_SYNTAX_ROLES)
    }

    fn referencing_candidate_files(
        &self,
        analyzer: &dyn IAnalyzer,
        _target: &CodeUnit,
        seed_files: &BTreeSet<ProjectFile>,
        cancellation: Option<&brokk_bifrost_core::cancellation::CancellationToken>,
    ) -> Option<HashSet<ProjectFile>> {
        resolve_analyzer::<CSharpAnalyzer>(analyzer)?
            .referencing_candidate_files(seed_files, cancellation)
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
        brokk_bifrost_analysis::analyzer::languages::with_resolved_analyzer::<CSharpAnalyzer, _>(
            analyzer,
            |csharp| csharp.ranges_limited(unit, limit),
        )
    }

    fn external_member_is_static(
        &self,
        analyzer: &dyn IAnalyzer,
        packs: Option<
            Arc<brokk_bifrost_analysis::analyzer::semantic_model::overlay::SemanticModelOverlay>,
        >,
        owner: &str,
        member: &str,
    ) -> Option<bool> {
        resolve_analyzer::<CSharpAnalyzer>(analyzer)?
            .external_member_is_static(packs, owner, member)
    }

    fn external_type_is_sealed(
        &self,
        analyzer: &dyn IAnalyzer,
        packs: Option<
            Arc<brokk_bifrost_analysis::analyzer::semantic_model::overlay::SemanticModelOverlay>,
        >,
        owner: &str,
    ) -> Option<bool> {
        resolve_analyzer::<CSharpAnalyzer>(analyzer)?.external_type_is_sealed(packs, owner)
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

    fn dependency_pack_resolver(
        &self,
    ) -> Option<&'static dyn brokk_bifrost_analysis::analyzer::semantic_model::dependency::DependencyResolver>{
        Some(&dependency_packs::DotNetDependencyResolver)
    }

    fn is_file_dependency_input(&self, path: &std::path::Path) -> bool {
        crate::analyzer::csharp::is_csharp_dependency_input_path(path)
    }

    fn call_argument_conversion_prover(
        &self,
    ) -> Option<&'static dyn brokk_bifrost_analysis::analyzer::usages::call_conversion::CallArgumentConversionProver>
{
        Some(&call_conversion::CALL_ARGUMENT_CONVERSION_PROVER)
    }

    fn reference_usage_strategy(
        &self,
    ) -> &'static dyn brokk_bifrost_analysis::analyzer::usages::traits::GraphUsageAnalyzer {
        &CSHARP_USAGE_STRATEGY
    }

    fn reference_graph_backend(
        &self,
    ) -> brokk_bifrost_analysis::analyzer::languages::LanguageGraphBackend {
        brokk_bifrost_analysis::analyzer::languages::LanguageGraphBackend::Legacy(&CSharpEdgePass)
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
        crate::analyzer::usages::get_definition::csharp::resolve_definition_dispatch(
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
        crate::analyzer::usages::get_definition::csharp::csharp_call_reference_candidate(node)
    }

    fn definition_boundary_evidence(
        &self,
        analyzer: &dyn brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer,
        token: brokk_bifrost_core::analyzer::query_token::QueryToken<'_>,
        file: &brokk_bifrost_core::analyzer::model::ProjectFile,
        name: &str,
    ) -> Option<(
        brokk_bifrost_core::analyzer::structural::resolution::BoundaryStatus,
        Option<String>,
    )> {
        use crate::analyzer::CSharpAnalyzer;

        use brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer;
        resolve_analyzer::<CSharpAnalyzer>(analyzer)
            .map(|csharp| csharp.external_boundary_evidence(token, file, name))
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
}

struct CSharpEdgePass;

impl LanguageEdgePass for CSharpEdgePass {
    fn id(&self) -> EdgePassId {
        EdgePassId::CSharp
    }

    fn edge_sites(&self, ctx: &EdgeSiteScanCtx<'_>) -> Option<LanguageEdgeSites> {
        brokk_bifrost_analysis::analyzer::languages::fqn_edge_sites(ctx, |token| {
            build_rooted_csharp_usage_edges(ctx.analyzer, token, ctx.fqns, ctx.keep_file)
        })
    }

    fn edge_weights(&self, ctx: &EdgeWeightScanCtx<'_>) -> Option<LanguageEdgeWeights> {
        brokk_bifrost_analysis::analyzer::languages::fqn_edge_weights(ctx, |token| {
            build_csharp_usage_edge_weights(ctx.analyzer, token, ctx.fqns, ctx.keep_file)
        })
    }
}

impl StructuralReceiverResolver for CSharpSupport {
    fn member_target_input_mode(&self) -> ReceiverSiteInputMode {
        ReceiverSiteInputMode::ContainingSite
    }

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
        brokk_bifrost_analysis::analyzer::languages::with_bounded_receiver_query(
            query,
            |query, token| {
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
            },
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
        ready_preflight(analyzer, Language::CSharp, "C#")
    }

    fn build(
        &self,
        analyzer: &dyn IAnalyzer,
        candidates: &[CodeUnit],
    ) -> Option<DeadCodeBulkEdges> {
        let csharp = resolve_analyzer::<CSharpAnalyzer>(analyzer)?;
        brokk_bifrost_analysis::analyzer::languages::build_fqn_dead_code_edges(
            analyzer,
            &csharp.memo_caches.dead_code_usage_edges,
            candidates,
            |token, callees| {
                build_inbound_csharp_usage_edges_with_completeness(analyzer, token, callees)
            },
        )
    }
}

impl brokk_bifrost_analysis::analyzer::multi_analyzer::LanguageAnalyzer for CSharpAnalyzer {
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
        Box::new(CSharpAnalyzer::clone_with_project(self, project))
    }

    fn clone_for_index_warm(
        &self,
        project: Arc<dyn Project>,
    ) -> Box<dyn brokk_bifrost_analysis::analyzer::multi_analyzer::LanguageAnalyzer> {
        Box::new(CSharpAnalyzer::clone_for_index_warm(self, project))
    }

    fn import_analysis_provider(&self) -> Option<&dyn ImportAnalysisProvider> {
        Some(self)
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
        Box::new(CSharpAnalyzer::update_all_with_progress(self, progress))
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

    use brokk_bifrost_analysis::analyzer::workspace::READS_FILES_ONLY;

    use brokk_bifrost_core::analyzer::config::AnalyzerConfig;

    use brokk_bifrost_core::analyzer::project::Project;

    use crate::analyzer::CSharpDependencyPackAdapter;

    use crate::analyzer::resolve_csharp_semantic_pack_dependencies;
    pub(crate) struct DotNetDependencyResolver;

    impl DependencyResolver for DotNetDependencyResolver {
        fn adapter(&self) -> &'static dyn DependencyPackAdapter {
            &CSharpDependencyPackAdapter
        }

        fn dependency_inputs(&self) -> &'static [&'static str] {
            &["project.assets.json"]
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
            resolve_csharp_semantic_pack_dependencies(&config.csharp, project, limits, cancellation)
        }
    }
}

#[cfg(test)]
mod dead_code_cache_tests {

    use crate::analyzer::csharp::*;

    use crate::inline_project::InlineTestProject;
    use brokk_bifrost_core::analyzer::usages::inverted_edges::UsageEdges;

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

        brokk_bifrost_analysis::analyzer::test_support::assert_dead_code_cache_reset_after_update_paths(
            &analyzer,
            &key,
            |analyzer| &analyzer.memo_caches.dead_code_usage_edges,
            |analyzer| analyzer.update(&std::collections::BTreeSet::new()),
            |analyzer| analyzer.update_all(),
            |analyzer| analyzer.clone_with_project(fixture.project_dyn()),
        );
    }
}

#[cfg(test)]
mod package_inventory_gate_tests {

    use crate::analyzer::csharp::*;

    use crate::inline_project::InlineTestProject;
    use brokk_bifrost_core::analyzer::project::OverlayProject;

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
