//! Kotlin analyzer: parsing, declaration indexing, persistence, and name
//! resolution.
//!
//! `KotlinAnalyzer` is a thin wrapper over the shared
//! [`TreeSitterAnalyzer`] engine: file enumeration, incremental updates,
//! persisted store round-trips, and every declaration-oriented query delegate
//! to the engine, with Kotlin-specific behavior isolated in
//! [`adapter::KotlinAdapter`] and [`declarations`] (issue #1236).
//!
//! Name resolution is split across [`imports`] (structured import facts and
//! the file relationships they create), [`supertypes`] (what a class-like
//! declaration extends), [`types`] (the resolution ladder), and [`hierarchy`]
//! (ancestors and descendants). Kotlin also joins the shared JVM realm here:
//! it reads the same jar-backed dependency index Java and Scala use, and
//! `MultiAnalyzer` widens its import and hierarchy resolution across Java and
//! Scala sources through `brokk_bifrost_jvm::realm` (issue #1237).
//!
//! Deliberate boundaries within Kotlin/JVM name resolution: Kotlin/JS and
//! Kotlin/Native default imports are not modelled, `expect`/`actual` pairs are
//! indexed as ordinary declarations with no link asserted between them, and a
//! type reachable only through an unconfigured classpath stays explicitly
//! unknown.
//!
//! Definition, declaration, type, hover, and signature navigation are live
//! (#1238); definition and type points use the shared selected native JVM
//! resolver in `crate::analyzer::jvm::native_points`. The usage graph retains
//! its existing Kotlin edge pass.
//!
//! Structural CodeQuery/RQL is live too (#1240): [`structural`] supplies the
//! [`brokk_bifrost_analysis::analyzer::structural::StructuralSpec`] the shared engine needs, so
//! `query_code` and `(language kotlin …)` search Kotlin files like any other
//! registered language.
//!
//! Executable-semantics lowering is live (#1241): [`semantic`] publishes a
//! versioned `ProgramSemanticsProvider`, and its module header documents the
//! source-level constructs that stay capability-scoped.
//!
//! Reference, usage, and call graphs are live (#1239). Both usage paths answer
//! for Kotlin: `crate::analyzer::usages::kotlin_graph` resolves "who uses this
//! declaration?" for `scan_usages`, LSP references, and reference-rewriting
//! rename, and builds the whole-workspace `caller -> callee` edge set behind
//! `usage_graph`, `callers`/`callees`, relevance ranking, and dead-code
//! detection. The shared JVM realm is symmetric for Kotlin: a Kotlin reference
//! resolves onto Java and Scala declarations, and a Java or Scala reference onto
//! Kotlin ones, in both usage paths.
//!
//! One realm asymmetry is *not* Kotlin's and is not closed here: Scala's own
//! edge builder resolves type names against the Scala-only declaration index, so
//! Scala source contributes no edges onto Java or Kotlin declarations. Java had
//! the same gap until #1239 milestone 4 gave its builder the realm-aware index;
//! Scala's resolver is structured differently and needs its own change.

#[doc(hidden)]
pub mod adapter;
mod clones;
pub(crate) mod diagnostics;
mod hierarchy;
pub(crate) mod imports;
pub(crate) mod language;
mod scalar;
mod semantic;
mod structural;
pub(crate) mod types;

pub use crate::analyzer::kotlin::scalar::kotlin_declared_scalar_types;

#[cfg(any(test, feature = "test-support"))]
use brokk_bifrost_analysis::delegate_inner_test_hook_methods;
use brokk_bifrost_analysis::{
    delegate_inner_methods, delegate_inner_procedure_fact_methods,
    forward_file_identity_invalidation, forward_relational_definition_batch,
    impl_forward_query_provider,
};

use brokk_bifrost_core::analyzer::model::Range;

use brokk_bifrost_core::analyzer::query_batch::LimitedQueryRows;

use brokk_bifrost_core::analyzer::query_token::QueryToken;
use brokk_bifrost_core::analyzer::structural::resolution::BoundaryStatus;
use brokk_bifrost_jvm::kotlin::graph_support::KotlinSource;
use brokk_bifrost_jvm::kotlin::imports::build_kotlin_top_level_declarations_by_package;

use brokk_bifrost_analysis::analyzer::clone_detection::detect_language_structural_clone_smells;

use brokk_bifrost_core::analyzer::common::language_for_file as file_language;

use crate::analyzer::jvm::dependency_discovery::is_jvm_dependency_input;

use crate::analyzer::jvm::external::JvmExternalDeclarationIndex;

use crate::analyzer::jvm::external::JvmExternalDeclarations;

use crate::analyzer::jvm::external::jvm_external_qualified_name_exists;

use crate::analyzer::jvm::retained_external_index_state;
mod call_applicability;

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

use brokk_bifrost_analysis::analyzer::languages::StructuralReceiverResolver;

use brokk_bifrost_analysis::analyzer::languages::fqn_has_multiple_function_definitions;

use brokk_bifrost_analysis::analyzer::languages::ready_preflight;

use brokk_bifrost_core::analyzer::pool_memo::KeyedPoolSafeMemo;

use brokk_bifrost_core::analyzer::pool_memo::PoolSafeMemo;

use brokk_bifrost_analysis::analyzer::usages::inverted_edges::UsageEdgesCache;

use brokk_bifrost_analysis::analyzer::usages::inverted_edges::weight_usage_edges;

use crate::analyzer::usages::kotlin_graph::KotlinUsageGraphStrategy;

use crate::analyzer::usages::kotlin_graph::build_inbound_kotlin_usage_edges_with_completeness;

use crate::analyzer::usages::kotlin_graph::build_kotlin_usage_edge_weights;

use brokk_bifrost_analysis::analyzer::usages::workspace_graph::UsageEcosystem;

use brokk_bifrost_core::analyzer::weighted_cache::build_weighted_cache;

use brokk_bifrost_core::analyzer::weighted_cache::weight_code_unit_set;

use brokk_bifrost_core::analyzer::weighted_cache::weight_code_unit_vec_by_unit;

use brokk_bifrost_core::analyzer::weighted_cache::weight_project_file_set;

use brokk_bifrost_core::analyzer::config::AnalyzerConfig;

use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::AnalyzerStoreContext;

use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::BuildProgress;

use brokk_bifrost_core::analyzer::model::CloneSmell;

use brokk_bifrost_core::analyzer::model::CloneSmellWeights;

use brokk_bifrost_core::analyzer::model::CodeUnit;

use brokk_bifrost_analysis::analyzer::analyzer_definition_lookup::ForwardQueryProvider;

use brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer;

use brokk_bifrost_core::analyzer::capabilities::ImportAnalysisProvider;

use brokk_bifrost_core::analyzer::config::JvmAnalyzerConfig;

use brokk_bifrost_core::analyzer::model::Language;

use brokk_bifrost_core::analyzer::project::Project;

use brokk_bifrost_core::analyzer::model::ProjectFile;

use brokk_bifrost_core::analyzer::model::SignatureMetadata;

use brokk_bifrost_core::analyzer::model::TestAssertionSmell;

use brokk_bifrost_core::analyzer::model::TestAssertionWeights;

use brokk_bifrost_core::analyzer::capabilities::TestDetectionProvider;

use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::TreeSitterAnalyzer;

use brokk_bifrost_core::analyzer::capabilities::TypeAliasProvider;

use brokk_bifrost_core::analyzer::capabilities::TypeHierarchyProvider;

use brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer;

use brokk_bifrost_core::hash::HashMap;

use brokk_bifrost_core::hash::HashSet;
use brokk_bifrost_jvm::kotlin::test_detection::detect_kotlin_test_assertion_smells;
use brokk_bifrost_jvm::proof::JvmRetainedExternalIndex;
use moka::sync::Cache;
use std::collections::BTreeSet;
use std::sync::{Arc, OnceLock};

use brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope;

use brokk_bifrost_core::analyzer::query_token::QueryScope;

#[doc(hidden)]
pub use crate::analyzer::kotlin::adapter::KotlinAdapter;

use crate::analyzer::kotlin::clones::build_kotlin_clone_candidate_data;

#[derive(Clone)]
pub struct KotlinAnalyzer {
    inner: TreeSitterAnalyzer<KotlinAdapter>,
    /// Kotlin's share of the JVM dependency realm: the same jar-backed index
    /// Java and Scala consult, built from the same discovered Maven/Gradle
    /// artifacts. Built lazily because opening jars is expensive and many
    /// workspaces never ask a question that needs it.
    jvm_config: JvmAnalyzerConfig,
    external_index: Arc<OnceLock<Arc<JvmExternalDeclarationIndex>>>,
    memo_budget: u64,
    imported_code_units: Cache<ProjectFile, Arc<HashSet<CodeUnit>>>,
    /// Import and hierarchy answers computed with the whole JVM source realm
    /// in view. Kept apart from the Kotlin-only caches above because they
    /// answer a strictly wider question: serving one for the other would
    /// silently drop, or invent, cross-language results.
    realm_imported_code_units: Cache<ProjectFile, Arc<HashSet<CodeUnit>>>,
    referencing_files: Cache<ProjectFile, Arc<HashSet<ProjectFile>>>,
    reverse_import_index: Arc<PoolSafeMemo<HashMap<ProjectFile, Arc<HashSet<ProjectFile>>>>>,
    /// Coarse import targets projected directly to files. Built before the
    /// parallel file-graph walk so that a large Kotlin workspace does not run
    /// one bounded definition query per import.
    file_dependency_index: Arc<OnceLock<imports::KotlinFileDependencyIndex>>,
    same_package_reference_index:
        Arc<PoolSafeMemo<HashMap<ProjectFile, Arc<HashSet<ProjectFile>>>>>,
    top_level_declarations_by_package: Arc<OnceLock<HashMap<String, Arc<Vec<CodeUnit>>>>>,
    direct_ancestors: Cache<CodeUnit, Arc<Vec<CodeUnit>>>,
    realm_direct_ancestors: Cache<CodeUnit, Arc<Vec<CodeUnit>>>,
    /// `PoolSafeMemo`, not `OnceLock`, for the same reason as the two sibling
    /// index cells above: these whole-workspace builds are reached from rayon
    /// workers during cold scans, and a blocking `get_or_init` parks every one
    /// of them behind the single initializer for its full duration.
    /// Keyed by [`DescendantIndexVariant`]: a request that excluded test files
    /// gets an index that was never built over them (issue #1748). Two cells at
    /// most, because the exclusion verdict is a pure function of the analyzer
    /// and the file.
    direct_descendant_index: Arc<
        KeyedPoolSafeMemo<
            brokk_bifrost_core::analyzer::capabilities::DescendantIndexVariant,
            brokk_bifrost_core::analyzer::capabilities::DirectDescendantIndex,
        >,
    >,
    realm_direct_descendant_index: Arc<
        KeyedPoolSafeMemo<
            brokk_bifrost_core::analyzer::capabilities::DescendantIndexVariant,
            brokk_bifrost_core::analyzer::capabilities::DirectDescendantIndex,
        >,
    >,
    dead_code_usage_edges: UsageEdgesCache,
}

impl_forward_query_provider!(KotlinAnalyzer);

#[cfg(test)]
mod hierarchy_tests;

impl KotlinAnalyzer {
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn tree_sitter_analyzer_for_test(&self) -> &TreeSitterAnalyzer<KotlinAdapter> {
        &self.inner
    }

    pub(crate) fn tree_sitter_analyzer(&self) -> &TreeSitterAnalyzer<KotlinAdapter> {
        &self.inner
    }

    pub(crate) fn update_all_with_progress(
        &self,
        progress: Option<brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::BuildProgress>,
    ) -> Self {
        Self::from_inner(
            self.inner.update_all_with_progress(progress),
            self.memo_budget,
            self.jvm_config.clone(),
        )
    }

    #[cfg(test)]
    pub(crate) fn relational_batch_reader_checkouts_for_test(&self) -> usize {
        self.inner
            .analyzer_store()
            .relational_batch_counts_for_test()
            .0
    }

    #[cfg(test)]
    pub(crate) fn reset_authoritative_file_state_reads_for_test(&self) {
        self.inner.reset_authoritative_file_state_reads_for_test();
    }

    #[cfg(test)]
    pub(crate) fn authoritative_file_state_reads_for_test(&self) -> usize {
        self.inner.authoritative_file_state_reads_for_test()
    }

    pub fn new(project: Arc<dyn Project>) -> Self {
        Self::new_with_config(project, AnalyzerConfig::default())
    }

    /// Hydrate many files' indexed state in one store round-trip.
    ///
    /// The whole-workspace usage-edge builder needs every Kotlin file's
    /// declarations and ranges at once. Pulling them one file at a time would go
    /// through the per-file LRU and evict the entries a user's interactive
    /// queries depend on, so the build would leave every subsequent `scan_usages`
    /// cold. Mirrors Java's and Scala's builders for the same reason.
    pub(crate) fn bulk_file_states(
        &self,
        files: impl IntoIterator<Item = ProjectFile>,
        source_mode: brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::BulkFileStateSource,
    ) -> brokk_bifrost_core::hash::HashMap<
        ProjectFile,
        brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::FileState,
    > {
        self.inner.bulk_file_states(files, source_mode)
    }

    delegate_inner_methods! {
        #[doc(hidden)]
        pub fn reset_full_hydration_count_for_test(&self);
    }

    delegate_inner_methods! {
        #[doc(hidden)]
        pub fn full_hydration_count_for_test(&self) -> usize;
    }

    #[doc(hidden)]
    pub fn bulk_hydration_count_for_test(&self) -> usize {
        self.inner.bulk_hydration_count_for_test()
    }

    #[cfg(test)]
    pub(crate) fn clear_retained_file_states_for_test(&mut self) {
        self.inner.clear_retained_file_states_for_test();
    }

    pub fn new_with_config(project: Arc<dyn Project>, config: AnalyzerConfig) -> Self {
        let jvm_config = config.jvm.clone();
        TreeSitterAnalyzer::wrap_with_config(
            config,
            |config| TreeSitterAnalyzer::new_with_config(project, KotlinAdapter, config),
            |inner, memo_budget| Self::from_inner(inner, memo_budget, jvm_config),
        )
    }

    fn from_inner(
        inner: TreeSitterAnalyzer<KotlinAdapter>,
        memo_budget: u64,
        jvm_config: JvmAnalyzerConfig,
    ) -> Self {
        Self {
            inner,
            jvm_config,
            external_index: Arc::new(OnceLock::new()),
            memo_budget,
            imported_code_units: build_weighted_cache(memo_budget / 8, weight_code_unit_set),
            realm_imported_code_units: build_weighted_cache(memo_budget / 8, weight_code_unit_set),
            referencing_files: build_weighted_cache(memo_budget / 8, weight_project_file_set),
            reverse_import_index: Arc::new(PoolSafeMemo::new()),
            file_dependency_index: Arc::new(OnceLock::new()),
            same_package_reference_index: Arc::new(PoolSafeMemo::new()),
            top_level_declarations_by_package: Arc::new(OnceLock::new()),
            direct_ancestors: build_weighted_cache(memo_budget / 16, weight_code_unit_vec_by_unit),
            realm_direct_ancestors: build_weighted_cache(
                memo_budget / 16,
                weight_code_unit_vec_by_unit,
            ),
            direct_descendant_index: Arc::new(KeyedPoolSafeMemo::new()),
            realm_direct_descendant_index: Arc::new(KeyedPoolSafeMemo::new()),
            dead_code_usage_edges: build_weighted_cache(memo_budget / 8, weight_usage_edges),
        }
    }

    pub fn from_project<P>(project: P) -> Self
    where
        P: Project + 'static,
    {
        Self::new(Arc::new(project))
    }

    pub(crate) fn new_with_config_store_context(
        project: Arc<dyn Project>,
        config: AnalyzerConfig,
        store_context: AnalyzerStoreContext,
        progress: Option<BuildProgress>,
    ) -> Result<Self, brokk_bifrost_analysis::analyzer::store::StoreError> {
        let jvm_config = config.jvm.clone();
        TreeSitterAnalyzer::try_wrap_with_config(
            config,
            |config| {
                TreeSitterAnalyzer::new_with_config_storage_context_and_progress(
                    project,
                    KotlinAdapter,
                    config,
                    store_context,
                    progress,
                )
            },
            |inner, memo_budget| Self::from_inner(inner, memo_budget, jvm_config),
        )
    }

    pub(crate) fn clone_with_project(&self, project: Arc<dyn Project>) -> Self {
        // A different project root means different files and a different
        // classpath, so nothing derived from either survives the move.
        Self::from_inner(
            self.inner.clone_with_project(project),
            self.memo_budget,
            self.jvm_config.clone(),
        )
    }

    pub(crate) fn clone_for_index_warm(&self, project: Arc<dyn Project>) -> Self {
        let mut clone = self.clone();
        clone.inner = clone.inner.clone_with_project(project);
        clone
    }

    /// Kotlin's view of the shared JVM dependency realm.
    pub(crate) fn external_declaration_index(&self) -> &JvmExternalDeclarationIndex {
        crate::analyzer::jvm::external::get_or_build_external_declaration_index(
            &self.external_index,
            &self.jvm_config,
            self.inner.project(),
            self.inner.analyzer_store(),
        )
    }

    /// The external declaration surface Kotlin resolution reads: the shared
    /// jar-backed index plus the declaration facts the activated semantic packs
    /// publish (#1893).
    ///
    /// `packs` is the *dispatching* analyzer's overlay; see
    /// [`crate::analyzer::JavaAnalyzer::resolve_type_name_with_external`] on
    /// why activation state arrives as a parameter.
    pub(crate) fn external_declarations(
        &self,
        packs: Option<
            Arc<brokk_bifrost_analysis::analyzer::semantic_model::overlay::SemanticModelOverlay>,
        >,
    ) -> JvmExternalDeclarations<'_> {
        JvmExternalDeclarations::new(self.external_declaration_index(), packs)
    }

    /// How far a lookup for `name` from `file` could see past the workspace,
    /// and the external type it landed on when it landed on one.
    ///
    /// The JVM half of boundary refinement, mirroring
    /// `JavaAnalyzer::external_boundary_evidence`: the name is resolved through
    /// Kotlin's own import ladder against the shared external declaration
    /// surface, so the trace classifies a spelling exactly as the
    /// resolver would see it. A hit is [`BoundaryStatus::ExternalIndexed`] with
    /// the resolved external type; a miss against an index whose producers
    /// reported truncation is [`BoundaryStatus::ExternalDeclaredUnindexed`],
    /// because the build declared artifacts the index never finished reading.
    #[doc(hidden)]
    pub fn external_boundary_evidence(
        &self,
        token: QueryToken<'_>,
        packs: Option<
            Arc<brokk_bifrost_analysis::analyzer::semantic_model::overlay::SemanticModelOverlay>,
        >,
        file: &ProjectFile,
        name: &str,
    ) -> (BoundaryStatus, Option<String>) {
        use brokk_bifrost_jvm::kotlin::types::{
            KotlinNameScope, KotlinTypeName, resolve_kotlin_type_name,
        };

        let external = self.external_declarations(packs.clone());
        let package_name = self.inner.package_name_of(file).unwrap_or_default();
        let imports = self.inner.import_info_of(token, file);
        let scope = KotlinNameScope {
            package_name: &package_name,
            imports: &imports,
            // The trace hands over a reference spelling without its enclosing
            // declaration; a file-level scope is the resolution every import
            // tier still sees.
            scope_owners: Vec::new(),
        };
        let declares = |candidate: &str| {
            external
                .resolve_qualified_name(candidate, &package_name)
                .is_some()
        };
        let type_evidence = match resolve_kotlin_type_name(name, &scope, declares) {
            KotlinTypeName::Resolved(fqn) => {
                brokk_bifrost_analysis::analyzer::languages::ExternalTypeBoundaryEvidence::Indexed(Some(fqn))
            }
            // Two star imports both name an indexed external type: the name is
            // certainly indexed, but no single target can be reported.
            KotlinTypeName::Ambiguous => {
                brokk_bifrost_analysis::analyzer::languages::ExternalTypeBoundaryEvidence::Indexed(None)
            }
            KotlinTypeName::Unresolved => {
                brokk_bifrost_analysis::analyzer::languages::ExternalTypeBoundaryEvidence::Unresolved
            }
        };
        // A member spelling leaves the workspace exactly as its owner type
        // does, so the member tier runs where the type tier found nothing
        // (#1900). A member the surface does not declare changes nothing.
        // One ladder answers here and in the resolver's own boundary gate, so
        // a trace and a definition cannot disagree about a spelling (#2287).
        brokk_bifrost_analysis::analyzer::languages::classify_jvm_external_boundary_evidence(
            type_evidence,
            || {
                self.resolve_member_name_with_external(token, packs, file, name)
                    .map(|member| member.fqn().to_owned())
            },
            || {
                self.external_declaration_index()
                    .production_diagnostic_count()
                    > 0
            },
        )
    }

    /// Resolve `raw_name` in `file` as a member spelling -- a written
    /// `Owner.member` whose head is a type Kotlin's import ladder reaches
    /// outside the workspace and whose last segment is a member the external
    /// declaration surface declares (#1900).
    ///
    /// This is the Kotlin counterpart of
    /// `JavaAnalyzer::resolve_member_name_with_external`, and it is what lets
    /// Kotlin's own unresolved-receiver paths reach the shared import-boundary
    /// gate (#2287) instead of dying with a plain miss. The owner runs through
    /// `resolve_kotlin_type_name`, so an aliased import (`import a.b.C as D`,
    /// written `D.member`) reaches the same declaration the alias names, and a
    /// name two star imports both bind stays unresolved rather than guessing.
    ///
    /// Only the external surface can answer here: a workspace owner's members
    /// are indexed, and the resolver either found them or did not.
    pub(crate) fn resolve_member_name_with_external(
        &self,
        token: QueryToken<'_>,
        packs: Option<
            Arc<brokk_bifrost_analysis::analyzer::semantic_model::overlay::SemanticModelOverlay>,
        >,
        file: &ProjectFile,
        raw_name: &str,
    ) -> Option<crate::analyzer::jvm::external::JvmExternalMember> {
        use brokk_bifrost_jvm::kotlin::types::{
            KotlinNameScope, KotlinTypeName, resolve_kotlin_type_name,
        };

        let normalized = raw_name.trim();
        if normalized.is_empty() {
            return None;
        }
        let external = self.external_declarations(packs);
        if external.is_empty() {
            return None;
        }
        let package_name = self.inner.package_name_of(file).unwrap_or_default();
        let imports = self.inner.import_info_of(token, file);
        let scope = KotlinNameScope {
            package_name: &package_name,
            imports: &imports,
            // A reference spelling arrives without its enclosing declaration;
            // a file-level scope is the resolution every import tier still
            // sees, and it is the same scope the trace's evidence tier uses.
            scope_owners: Vec::new(),
        };
        let declares = |candidate: &str| {
            external
                .resolve_qualified_name(candidate, &package_name)
                .is_some()
        };
        external.resolve_member_spelling(normalized, &package_name, |owner_spelling| {
            match resolve_kotlin_type_name(owner_spelling, &scope, declares) {
                KotlinTypeName::Resolved(fqn) => {
                    external.resolve_qualified_name(&fqn, &package_name)
                }
                KotlinTypeName::Ambiguous | KotlinTypeName::Unresolved => None,
            }
        })
    }

    /// Row-capped projections for bounded receiver queries (issue #1242).
    ///
    /// A bounded query must be able to observe exhaustion before an unbounded
    /// row set is cloned, which the unbounded `IAnalyzer` accessors cannot
    /// report.
    pub(crate) fn signature_metadata_limited(
        &self,
        code_unit: &CodeUnit,
        limit: usize,
    ) -> brokk_bifrost_core::analyzer::query_batch::LimitedQueryRows<SignatureMetadata> {
        self.inner.signature_metadata_limited(code_unit, limit)
    }

    pub(crate) fn signatures_limited(
        &self,
        code_unit: &CodeUnit,
        limit: usize,
    ) -> brokk_bifrost_core::analyzer::query_batch::LimitedQueryRows<String> {
        self.inner.signatures_limited(code_unit, limit)
    }

    pub(crate) fn ranges_limited(
        &self,
        code_unit: &CodeUnit,
        limit: usize,
    ) -> brokk_bifrost_core::analyzer::query_batch::LimitedQueryRows<
        brokk_bifrost_core::analyzer::model::Range,
    > {
        self.inner.ranges_limited(code_unit, limit)
    }
}

impl TypeAliasProvider for KotlinAnalyzer {
    fn is_type_alias(&self, code_unit: &CodeUnit) -> bool {
        self.inner.is_type_alias(code_unit)
    }
}

impl KotlinSource for KotlinAnalyzer {
    fn all_files(&self) -> Vec<ProjectFile> {
        self.inner.all_files()
    }

    fn package_name_of(&self, file: &ProjectFile) -> Option<String> {
        self.inner.package_name_of(file)
    }

    fn with_usage_definitions(
        &self,
        _token: QueryToken<'_>,
        read: &mut dyn FnMut(
            &dyn brokk_bifrost_core::analyzer::definition_lookup::BoundedDefinitionLookup,
        ),
    ) {
        brokk_bifrost_analysis::analyzer::with_analyzer_usage_definitions(
            self,
            Language::Kotlin,
            read,
        );
    }

    fn type_identifiers_of(&self, file: &ProjectFile) -> Option<HashSet<String>> {
        self.inner.type_identifiers_of(file)
    }

    delegate_inner_methods! {
        fn raw_supertypes_of(&self, code_unit: &CodeUnit) -> Vec<String>;
    }

    fn resolved_ancestors_from_hydrated_facts(
        &self,
        token: QueryToken<'_>,
        owner: &CodeUnit,
        raw_supertypes: &[String],
        imports: &[brokk_bifrost_core::analyzer::model::ImportInfo],
        realm: Option<&brokk_bifrost_jvm::realm::JvmSourceRealm<'_>>,
        type_by_fqn: &mut dyn FnMut(&str) -> Option<CodeUnit>,
    ) -> Vec<CodeUnit> {
        let cache = match realm {
            Some(_) => &self.realm_direct_ancestors,
            None => &self.direct_ancestors,
        };
        if let Some(cached) = cache.get(owner) {
            return (*cached).clone();
        }
        let ancestors = brokk_bifrost_jvm::kotlin::hierarchy::kotlin_resolve_ancestors_from_facts(
            self,
            token,
            owner,
            raw_supertypes,
            imports,
            realm,
            type_by_fqn,
        );
        cache.insert(owner.clone(), Arc::new(ancestors.clone()));
        ancestors
    }

    /// Built once per analyzer generation: a star import has to widen to a
    /// whole package, and repeating that scan per file would be quadratic in
    /// workspace size.
    fn top_level_declarations_by_package(&self) -> &HashMap<String, Arc<Vec<CodeUnit>>> {
        self.top_level_declarations_by_package
            .get_or_init(|| build_kotlin_top_level_declarations_by_package(self))
    }

    fn external_index_is_empty(&self) -> bool {
        self.external_declaration_index().is_empty()
    }

    fn external_qualified_name_exists(&self, fqn: &str, access_package: &str) -> bool {
        jvm_external_qualified_name_exists(self.external_declaration_index(), fqn, access_package)
    }

    fn retained_external_index(&self) -> JvmRetainedExternalIndex {
        retained_external_index_state(self.external_index.get().map(Arc::as_ref))
    }

    fn retained_external_qualified_name_exists(&self, fqn: &str, access_package: &str) -> bool {
        self.external_index.get().is_some_and(|external| {
            jvm_external_qualified_name_exists(external, fqn, access_package)
        })
    }
}

use brokk_bifrost_core::analyzer::code_unit_index::CodeUnitIndex;

impl CodeUnitIndex for KotlinAnalyzer {
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

    fn summary_file_projection(
        &self,
        file: &ProjectFile,
    ) -> Option<Arc<brokk_bifrost_core::analyzer::model::SummaryFileProjection>> {
        self.inner
            .summary_file_projection(file)
            .map(brokk_bifrost_analysis::analyzer::common::non_synthetic_summary_projection)
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

    fn direct_children(&self, code_unit: &CodeUnit) -> Vec<CodeUnit> {
        brokk_bifrost_analysis::analyzer::common::non_synthetic_children(
            self.inner.direct_children(code_unit),
        )
    }

    fn parent_of(&self, code_unit: &CodeUnit) -> Option<CodeUnit> {
        CodeUnitIndex::parent_of(&self.inner, code_unit)
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
        let rendered =
            brokk_bifrost_analysis::analyzer::common::render_skeleton(self, code_unit, false);
        brokk_bifrost_analysis::analyzer::common::normalize_skeleton(rendered)
    }

    fn get_skeleton_header(&self, code_unit: &CodeUnit) -> Option<String> {
        let rendered =
            brokk_bifrost_analysis::analyzer::common::render_skeleton(self, code_unit, true);
        brokk_bifrost_analysis::analyzer::common::normalize_skeleton(rendered)
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

impl IAnalyzer for KotlinAnalyzer {
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

    fn semantic_diagnostics(
        &self,
        file: &ProjectFile,
        source: &str,
    ) -> brokk_bifrost_core::analyzer::model::SemanticDiagnosticReport {
        let scope = AnalyzerQueryScope::new(self);
        let token = scope.token();
        diagnostics::collect_kotlin_semantic_diagnostics(self, token, file, source, None)
    }

    /// Build the jar-backed external declaration index off the request path.
    /// See `JavaAnalyzer::warm_query_indexes`; the three JVM analyzers share
    /// one dependency universe and one reason not to build it under a
    /// diagnostic.
    fn warm_query_indexes(&self) {
        self.external_declaration_index();
    }

    fn query_indexes_warm(&self) -> bool {
        self.external_index.get().is_some()
    }

    fn external_dispatch_behavior_identity(
        &self,
    ) -> Option<brokk_bifrost_analysis::analyzer::semantic::StableDigest> {
        Some(
            self.external_declaration_index()
                .dispatch_behavior_identity(),
        )
    }

    fn update(&self, changed_files: &BTreeSet<ProjectFile>) -> Self {
        // Every import- and package-derived index is rebuilt from the new
        // generation: an edit anywhere can add, remove, or rename a
        // declaration that some other file's import resolves to.
        let mut updated = Self::from_inner(
            self.inner.update(changed_files),
            self.memo_budget,
            self.jvm_config.clone(),
        );
        updated.external_index = brokk_bifrost_analysis::analyzer::updated_external_index(
            &self.external_index,
            changed_files,
            is_jvm_dependency_input,
        );
        updated
    }

    fn update_all(&self) -> Self {
        self.update_all_with_progress(None)
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

    /// Kotlin answers the external-root half of the member-family capability
    /// (workspace implementors of one exact JDK member, #2580) and reports
    /// `unsupported` for a workspace member's own family; see the provider impl
    /// in `analyzer/kotlin/hierarchy.rs`.
    fn member_family_provider(
        &self,
    ) -> Option<&dyn brokk_bifrost_analysis::analyzer::usages::member_family::MemberFamilyProvider>
    {
        Some(self)
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

    delegate_inner_methods! {
        fn contains_tests(&self, file: &ProjectFile) -> bool;
    }

    fn contains_tests_for_changed_file(&self, file: &ProjectFile) -> bool {
        let contains_tests = self.contains_tests(file);
        if contains_tests || file_language(file) != Language::Kotlin {
            return contains_tests;
        }
        let Ok(source) = self.inner.project().read_source(file) else {
            return false;
        };
        brokk_bifrost_jvm::kotlin::test_detection::kotlin_changed_file_contains_tests(file, &source)
    }

    fn in_test_region(&self, code_unit: &CodeUnit) -> bool {
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
        detect_language_structural_clone_smells(
            self,
            files,
            weights,
            Language::Kotlin,
            |code_unit| build_kotlin_clone_candidate_data(self, code_unit, weights),
        )
    }

    fn find_test_assertion_smells(
        &self,
        file: &ProjectFile,
        weights: TestAssertionWeights,
    ) -> Vec<TestAssertionSmell> {
        brokk_bifrost_analysis::analyzer::test_assertion_smells_for_file(
            self,
            file,
            Language::Kotlin,
            |source| detect_kotlin_test_assertion_smells(self, file, source, &weights),
        )
    }

    fn test_detection_provider(&self) -> Option<&dyn TestDetectionProvider> {
        Some(self)
    }
}

#[cfg(any(test, feature = "test-support"))]
impl brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerTestHooks for KotlinAnalyzer {
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

impl TestDetectionProvider for KotlinAnalyzer {}

static KOTLIN_USAGE_STRATEGY: KotlinUsageGraphStrategy = KotlinUsageGraphStrategy::new();

/// Kotlin point consumers use the selected native JVM resolver in every build.
pub(crate) fn native_kotlin_selected() -> bool {
    true
}

impl brokk_bifrost_analysis::analyzer::multi_analyzer::LanguageAnalyzer for KotlinAnalyzer {
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
        Box::new(KotlinAnalyzer::clone_with_project(self, project))
    }

    fn clone_for_index_warm(
        &self,
        project: Arc<dyn Project>,
    ) -> Box<dyn brokk_bifrost_analysis::analyzer::multi_analyzer::LanguageAnalyzer> {
        Box::new(KotlinAnalyzer::clone_for_index_warm(self, project))
    }

    fn import_analysis_provider(&self) -> Option<&dyn ImportAnalysisProvider> {
        Some(self)
    }

    fn type_hierarchy_provider(
        &self,
    ) -> Option<&dyn brokk_bifrost_core::analyzer::capabilities::TypeHierarchyProvider> {
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
        Box::new(KotlinAnalyzer::update_all_with_progress(self, progress))
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

#[doc(hidden)]
pub struct KotlinSupport;

static KOTLIN_DEAD_CODE_BULK: KotlinDeadCodeBulk = KotlinDeadCodeBulk;

struct KotlinDeadCodeBulk;

#[derive(Default)]
struct KotlinDeadCodeMemo {
    overloaded_fqns: HashMap<String, bool>,
}

impl DeadCodeBulkProof for KotlinDeadCodeBulk {
    fn id(&self) -> EdgePassId {
        EdgePassId::Kotlin
    }

    fn new_memo(&self) -> Box<dyn std::any::Any + Send> {
        Box::new(KotlinDeadCodeMemo::default())
    }

    fn needs_precise_scan(&self, routing: DeadCodeRouting<'_>) -> bool {
        let KotlinDeadCodeMemo { overloaded_fqns } =
            routing.memo.downcast_mut().expect("Kotlin bulk memo");
        // Kotlin properties are represented as fields in the analyzer index,
        // while the inverted Kotlin resolver's complete target model is for
        // classes and callable declarations. Keep fields on the existing
        // precise path until the property accessor contract is explicit.
        if !routing.candidate.is_function() && !routing.candidate.is_class() {
            return true;
        }
        if !routing.candidate.is_function() {
            return false;
        }
        let fqn = routing.candidate.fq_name();
        *overloaded_fqns.entry(fqn.clone()).or_insert_with(|| {
            fqn_has_multiple_function_definitions(routing.analyzer, Language::Kotlin, &fqn)
        })
    }

    fn preflight(&self, analyzer: &dyn IAnalyzer) -> DeadCodeBulkPreflight {
        ready_preflight(analyzer, Language::Kotlin, "Kotlin")
    }

    fn build(
        &self,
        analyzer: &dyn IAnalyzer,
        candidates: &[CodeUnit],
    ) -> Option<DeadCodeBulkEdges> {
        let cancellation = analyzer.active_query_cancellation().unwrap_or_default();
        if cancellation.is_cancelled() {
            return None;
        }
        let _scope = AnalyzerQueryScope::with_cancellation(analyzer, &cancellation);
        let kotlin = resolve_analyzer::<KotlinAnalyzer>(analyzer)?;
        brokk_bifrost_analysis::analyzer::languages::build_fqn_dead_code_edges(
            analyzer,
            &kotlin.dead_code_usage_edges,
            candidates,
            |token, callees| {
                build_inbound_kotlin_usage_edges_with_completeness(analyzer, token, callees)
            },
        )
    }
}

impl KotlinSupport {
    /// The Kotlin delegate, together with a view of the whole JVM source realm,
    /// when this workspace has Kotlin alongside at least one other JVM
    /// language.
    ///
    /// A Kotlin analyzer only indexes `.kt` files, so on its own it cannot see
    /// that the interface a Kotlin class implements is declared in a Java file
    /// next door. `MultiAnalyzer` is the only place that holds every delegate,
    /// so the realm view is built from it. `None` means the widening
    /// would add nothing and the delegate's own answer already stands.
    fn kotlin_realm(
        workspace: &brokk_bifrost_analysis::analyzer::multi_analyzer::MultiAnalyzer,
    ) -> Option<(
        &KotlinAnalyzer,
        brokk_bifrost_jvm::realm::JvmSourceRealm<'_>,
    )> {
        let kotlin = workspace
            .delegates()
            .get(&Language::Kotlin)?
            .as_any()
            .downcast_ref::<KotlinAnalyzer>()?;
        let realm = crate::analyzer::jvm::realm_builder::jvm_source_realm(workspace);
        realm
            .has_peers_of(Language::Kotlin)
            .then_some((kotlin, realm))
    }
}

impl LanguageSupport for KotlinSupport {
    fn call_reference_candidate_override(&self, node: tree_sitter::Node<'_>) -> Option<bool> {
        Some(crate::analyzer::usages::get_definition::kotlin::kotlin_call_reference_candidate(node))
    }

    /// A Kotlin file can import a Java or Scala declaration from the same
    /// workspace, and only the workspace dispatcher can see both sides.
    fn workspace_imported_code_units(
        &self,
        workspace: &brokk_bifrost_analysis::analyzer::multi_analyzer::MultiAnalyzer,
        token: QueryToken<'_>,
        file: &ProjectFile,
    ) -> Option<Arc<HashSet<CodeUnit>>> {
        let (kotlin, realm) = Self::kotlin_realm(workspace)?;
        Some(kotlin.imported_code_units_in_realm(token, file, Some(&realm)))
    }
    /// A Kotlin class can extend a Java class or implement a Scala trait
    /// declared in the same workspace; resolving that needs every JVM
    /// delegate, which only the workspace dispatcher holds.
    fn workspace_direct_ancestors(
        &self,
        workspace: &brokk_bifrost_analysis::analyzer::multi_analyzer::MultiAnalyzer,
        token: QueryToken<'_>,
        unit: &CodeUnit,
    ) -> Option<Vec<CodeUnit>> {
        let (kotlin, realm) = Self::kotlin_realm(workspace)?;
        Some(kotlin.direct_ancestors_in_realm(token, unit, Some(&realm)))
    }
    fn workspace_direct_ancestors_within(
        &self,
        workspace: &brokk_bifrost_analysis::analyzer::multi_analyzer::MultiAnalyzer,
        token: QueryToken<'_>,
        unit: &CodeUnit,
        scope: &brokk_bifrost_core::analyzer::capabilities::DescendantIndexScope<'_>,
    ) -> Option<Option<Vec<CodeUnit>>> {
        let (kotlin, realm) = Self::kotlin_realm(workspace)?;
        Some(
            (!scope.cancellation().is_cancelled())
                .then(|| kotlin.direct_ancestors_in_realm(token, unit, Some(&realm))),
        )
    }
    fn workspace_additional_direct_descendants(
        &self,
        workspace: &brokk_bifrost_analysis::analyzer::multi_analyzer::MultiAnalyzer,
        token: QueryToken<'_>,
        unit: &CodeUnit,
        scope: &brokk_bifrost_core::analyzer::capabilities::DescendantIndexScope<'_>,
    ) -> Option<HashSet<CodeUnit>> {
        // Kotlin subclasses of a Java or Scala type are invisible to that
        // language's own descendant index, which only walks its own
        // declarations. Kotlin's realm-aware index does resolve across the
        // realm, so folding it in is what makes `Api`'s Kotlin implementors
        // show up.
        //
        // The reverse direction, Java and Scala subclasses of a Kotlin type,
        // is still missing, and cannot be fixed here. Each language's
        // descendant index is the inverse of its own ancestor resolution, and
        // Java's and Scala's resolve a spelled supertype against their own
        // declarations only; folding their indexes in for a Kotlin unit would
        // fold in indexes that never saw the Kotlin declaration in the first
        // place. Closing it means giving those two hierarchy resolvers the
        // realm-aware existence predicate Kotlin's already has (`realm_type_exists`
        // / `realm_type_by_fqn` in `kotlin/hierarchy.rs`), a change to those
        // analyzers, not to this hook. Issue #1239 made usage resolution
        // realm-aware in both directions; hierarchy resolution is a separate
        // seam and remains one-directional.
        if brokk_bifrost_core::analyzer::common::language_for_file(unit.source())
            != Language::Kotlin
            && let Some((kotlin, realm)) = Self::kotlin_realm(workspace)
        {
            return kotlin.direct_descendants_in_realm(token, unit, Some(&realm), scope);
        }
        Some(HashSet::default())
    }
    fn default_definition_points(&self) -> Option<&'static dyn StructuralReceiverResolver> {
        self.structural_receiver()
    }
    fn workspace_external_member_family(
        &self,
        workspace: &brokk_bifrost_analysis::analyzer::multi_analyzer::MultiAnalyzer,
        identity: &brokk_bifrost_jvm::realm::JvmExternalMemberIdentity,
        max_visits: usize,
        cancellation: Option<&brokk_bifrost_core::cancellation::CancellationToken>,
    ) -> brokk_bifrost_analysis::analyzer::usages::member_family::ExternalMemberFamilyAnswer {
        if let Some(language) = [Language::Java, Language::Scala]
            .into_iter()
            .find(|language| workspace.languages().contains(language))
        {
            return brokk_bifrost_analysis::analyzer::usages::member_family::ExternalMemberFamilyAnswer::incomplete(
                    brokk_bifrost_analysis::analyzer::usages::member_family::ExternalMemberFamilyIncompleteReason::MixedJvmRealmUnsupported(
                        language,
                    ),
                    0,
                );
        }
        let Some(kotlin) = resolve_analyzer::<KotlinAnalyzer>(workspace) else {
            return brokk_bifrost_analysis::analyzer::usages::member_family::ExternalMemberFamilyAnswer::unsupported();
        };
        kotlin.resolve_external_member_family(workspace, identity, max_visits, cancellation)
    }
    fn workspace_semantic_diagnostics(
        &self,
        workspace: &brokk_bifrost_analysis::analyzer::multi_analyzer::MultiAnalyzer,
        token: QueryToken<'_>,
        file: &ProjectFile,
        source: &str,
    ) -> Option<brokk_bifrost_core::analyzer::model::SemanticDiagnosticReport> {
        // JVM diagnostics must see the same wider JVM source realm that import
        // and hierarchy resolution see: otherwise a type declared in a Java or
        // Scala sibling file would be misreported as unrecognized.
        //
        // Every Kotlin file routes here, not only one with Java or Scala
        // peers: the realm widens resolution, but the active dependency model
        // that decides whether a miss is provable is published on the
        // dispatcher either way. Falling through to the delegate for a
        // Kotlin-only workspace would read its empty overlay and suppress
        // every unknown name.
        //
        // The workspace, not the Kotlin delegate, for the same reason, plus
        // the enclosing-declaration lookup, which crosses languages. The shim
        // downcasts to the Kotlin analyzer itself.
        let realm = Self::kotlin_realm(workspace).map(|(_, realm)| realm);
        Some(diagnostics::collect_kotlin_semantic_diagnostics(
            workspace,
            token,
            file,
            source,
            realm.as_ref(),
        ))
    }
    fn definition_boundary_evidence(
        &self,
        analyzer: &dyn IAnalyzer,
        token: QueryToken<'_>,
        file: &ProjectFile,
        name: &str,
    ) -> Option<(
        brokk_bifrost_core::analyzer::structural::resolution::BoundaryStatus,
        Option<String>,
    )> {
        resolve_analyzer::<KotlinAnalyzer>(analyzer).map(|kotlin| {
            kotlin.external_boundary_evidence(token, analyzer.semantic_model_overlay(), file, name)
        })
    }
    #[cfg(any(test, feature = "test-support"))]
    fn probe_assignment_value(
        &self,
        query: brokk_bifrost_analysis::analyzer::languages::BoundedReceiverQuery<'_>,
        _request: &brokk_bifrost_core::analyzer::usages::reference_site::SourceLocationRequest,
        _cancellation: &brokk_bifrost_core::cancellation::CancellationToken,
    ) -> Result<
        Option<
            brokk_bifrost_core::analyzer::usages::resolution_session::BoundedResolution<
                brokk_bifrost_analysis::analyzer::native_points::NativeAssignmentValueProbe,
            >,
        >,
        String,
    > {
        Ok(Some(
            brokk_bifrost_analysis::analyzer::native_points::probe_jvm_assignment_value(
                resolve_analyzer::<KotlinAnalyzer>(query.analyzer)
                    .ok_or("assignment-value probe has no Kotlin analyzer")?
                    .tree_sitter_analyzer(),
                query,
            ),
        ))
    }

    #[cfg(any(test, feature = "test-support"))]
    fn selected_reverse_reference_file<'a>(
        &self,
        analyzer: &'a dyn IAnalyzer,
        _target_analyzer: &'a dyn IAnalyzer,
        file: &ProjectFile,
    ) -> brokk_bifrost_analysis::analyzer::store::Result<
        brokk_bifrost_analysis::analyzer::structural::reference_edges::SelectedReferenceFileProjection<'a>,
    >{
        let caller = resolve_analyzer::<KotlinAnalyzer>(analyzer).ok_or_else(|| {
            brokk_bifrost_analysis::analyzer::store::StoreError::new(format!(
                "selected reverse caller analyzer is unavailable: {file}"
            ))
        })?;
        brokk_bifrost_analysis::analyzer::structural::reference_edges::SelectedReferenceFileProjection::new(
            caller,
            analyzer,
            file,
            |source| {
                caller
                    .inner
                    .source_matches_selected_native_content(file, source)
            },
        )
    }

    fn knowledge(
        &self,
    ) -> &'static dyn brokk_bifrost_core::analyzer::language_knowledge::LanguageKnowledge {
        &brokk_bifrost_jvm::KotlinKnowledge
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
                KotlinAnalyzer::new_with_config_store_context(
                    project,
                    config,
                    store_context,
                    progress,
                )?,
            ),
        )
    }

    fn is_configuration_input(&self, file: &ProjectFile) -> bool {
        crate::analyzer::jvm::dependency_discovery::is_jvm_dependency_input(file)
    }

    fn definition_site_for_focus(
        &self,
        site: brokk_bifrost_core::analyzer::usages::reference_site::ResolvedReferenceSite,
        tree: &tree_sitter::Tree,
        source: &str,
        _start: Option<usize>,
        _end: Option<usize>,
    ) -> brokk_bifrost_core::analyzer::usages::reference_site::ResolvedReferenceSite {
        crate::analyzer::usages::get_definition::kotlin::kotlin_site_for_focus(site, tree, source)
    }

    fn native_member_attribution(
        &self,
        context: &brokk_bifrost_analysis::analyzer::store::resolution_operation::native_units::ProjectedNativeMemberContext,
        _outcome: brokk_bifrost_core::analyzer::structural::resolution::CandidateOutcome,
    ) -> Option<brokk_bifrost_analysis::analyzer::languages::NativeMemberAttribution> {
        use brokk_bifrost_analysis::analyzer::resolution::fact_resolution::FactMemberRouteKind;

        use brokk_bifrost_core::analyzer::structural::resolution::HierarchyRelation;

        use brokk_bifrost_core::analyzer::structural::resolution::MemberDispatchTier;

        use brokk_bifrost_core::analyzer::structural::resolution::PrecedenceTier;
        let depth = context.owner_path.len() - 1;
        let (dispatch_tier, relation, precedence_tier) = match context.route_kind {
            FactMemberRouteKind::Member | FactMemberRouteKind::KotlinCandidate => {
                return Some(crate::analyzer::jvm::native_member_attribution(context));
            }
            FactMemberRouteKind::Extension => {
                assert_eq!(depth, 0, "an exact extension receiver is its owner");
                (
                    MemberDispatchTier::Extension,
                    HierarchyRelation::Supertype,
                    PrecedenceTier::OwnMember,
                )
            }
            FactMemberRouteKind::TypeQualified => (
                MemberDispatchTier::StaticOrCompanion,
                HierarchyRelation::Embedded,
                PrecedenceTier::OwnMember,
            ),
        };
        Some(
            brokk_bifrost_analysis::analyzer::languages::NativeMemberAttribution {
                dispatch_tier,
                relation,
                precedence_tier,
            },
        )
    }

    fn external_inventory_providers(
        &self,
        analyzer: &dyn brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer,
    ) -> Vec<String> {
        crate::analyzer::jvm::external::kotlin_inventory_providers(analyzer)
    }

    #[cfg(any(test, feature = "test-support"))]
    fn native_rollout_points(
        &self,
    ) -> Option<&'static dyn brokk_bifrost_analysis::analyzer::languages::StructuralReceiverResolver>
    {
        self.structural_receiver()
    }

    fn procedure_syntax_roles(
        &self,
    ) -> Option<brokk_bifrost_analysis::analyzer::languages::ProcedureSyntaxRoles> {
        Some(semantic::PROCEDURE_SYNTAX_ROLES)
    }

    fn expand_imported_external_callee(
        &self,
        analyzer: &dyn IAnalyzer,
        file: &ProjectFile,
        callee_text: &str,
        _site: Option<&ExternalCalleeSite<'_>>,
    ) -> Option<ImportedExternalCallee> {
        let scope = AnalyzerQueryScope::new(analyzer);
        let kotlin = resolve_analyzer::<KotlinAnalyzer>(analyzer)?;
        kotlin
            .resolve_member_name_with_external(
                scope.token(),
                analyzer.semantic_model_overlay(),
                file,
                callee_text,
            )
            .map(|member| ImportedExternalCallee::text(member.fqn()))
    }

    fn signature_metadata_limited(
        &self,
        analyzer: &dyn IAnalyzer,
        unit: &CodeUnit,
        limit: usize,
    ) -> Option<LimitedQueryRows<SignatureMetadata>> {
        resolve_analyzer::<KotlinAnalyzer>(analyzer)
            .map(|kotlin| kotlin.signature_metadata_limited(unit, limit))
    }

    fn signatures_limited(
        &self,
        analyzer: &dyn IAnalyzer,
        unit: &CodeUnit,
        limit: usize,
    ) -> Option<LimitedQueryRows<String>> {
        resolve_analyzer::<KotlinAnalyzer>(analyzer)
            .map(|kotlin| kotlin.signatures_limited(unit, limit))
    }

    fn declaration_ranges_limited(
        &self,
        analyzer: &dyn IAnalyzer,
        unit: &CodeUnit,
        limit: usize,
    ) -> Option<LimitedQueryRows<Range>> {
        brokk_bifrost_analysis::analyzer::languages::with_resolved_analyzer::<KotlinAnalyzer, _>(
            analyzer,
            |kotlin| kotlin.ranges_limited(unit, limit),
        )
    }

    fn forward_query_provider<'a>(
        &self,
        analyzer: &'a dyn IAnalyzer,
    ) -> Option<&'a dyn ForwardQueryProvider> {
        brokk_bifrost_analysis::analyzer::multi_analyzer::forward_query_provider::<KotlinAnalyzer>(
            analyzer,
        )
    }

    fn ecosystem(&self) -> UsageEcosystem {
        UsageEcosystem::Jvm
    }

    fn reference_usage_strategy(
        &self,
    ) -> &'static dyn brokk_bifrost_analysis::analyzer::usages::traits::GraphUsageAnalyzer {
        &KOTLIN_USAGE_STRATEGY
    }

    fn reference_graph_backend(
        &self,
    ) -> brokk_bifrost_analysis::analyzer::languages::LanguageGraphBackend {
        brokk_bifrost_analysis::analyzer::languages::LanguageGraphBackend::Legacy(&KotlinEdgePass)
    }

    fn dead_code(&self) -> DeadCodeSupport {
        DeadCodeSupport {
            strategy: Some(&KOTLIN_USAGE_STRATEGY),
            bulk: Some(&KOTLIN_DEAD_CODE_BULK),
        }
    }

    fn structural_receiver(&self) -> Option<&'static dyn StructuralReceiverResolver> {
        native_kotlin_selected().then_some(
            &crate::analyzer::jvm::native_points::JVM_NATIVE_ROLLOUT_POINTS
                as &dyn StructuralReceiverResolver,
        )
    }
}
impl brokk_bifrost_analysis::analyzer::store::StoreLanguageSupport for KotlinSupport {
    fn root_source_horizon_follows_provenance(&self) -> bool {
        // Local identities stay in their host mount, including nonshared stage
        // allocations. Selected root and JVM bridges cannot classify as Import
        // or Reference source halves in another mount.
        true
    }

    fn is_configuration_input_path(&self, path: &std::path::Path) -> bool {
        crate::analyzer::jvm::is_jvm_configuration_input_path(path)
    }
fn call_applicability_adapter(
        &self,
    ) -> Option<&'static dyn brokk_bifrost_analysis::analyzer::resolution::fact_resolution::call_applicability::CallApplicabilityAdapter>{
        Some(&call_applicability::KOTLIN_CALL_APPLICABILITY_ADAPTER)
    }
}

/// One of three distinct JVM passes. Java, Scala and Kotlin resolve over the same
/// candidate space but scan only files of their own language, so the three passes cover
/// disjoint call sites and merge without double counting.
struct KotlinEdgePass;

impl LanguageEdgePass for KotlinEdgePass {
    fn id(&self) -> EdgePassId {
        EdgePassId::Kotlin
    }

    fn edge_sites(&self, ctx: &EdgeSiteScanCtx<'_>) -> Option<LanguageEdgeSites> {
        brokk_bifrost_analysis::analyzer::languages::fqn_edge_sites(ctx, |token| {
            crate::analyzer::usages::kotlin_graph::build_rooted_kotlin_usage_edges(
                ctx.analyzer,
                token,
                ctx.fqns,
                ctx.keep_file,
            )
        })
    }

    fn edge_weights(&self, ctx: &EdgeWeightScanCtx<'_>) -> Option<LanguageEdgeWeights> {
        brokk_bifrost_analysis::analyzer::languages::fqn_edge_weights(ctx, |token| {
            build_kotlin_usage_edge_weights(ctx.analyzer, token, ctx.fqns, ctx.keep_file)
        })
    }
}

#[cfg(test)]
mod dead_code_cache_tests {

    use crate::analyzer::kotlin::*;

    use crate::inline_project::InlineTestProject;
    use brokk_bifrost_core::analyzer::usages::inverted_edges::UsageEdges;

    #[test]
    fn update_all_update_and_overlay_clone_start_with_empty_dead_code_caches() {
        let fixture = InlineTestProject::with_language(Language::Kotlin)
            .file("A.kt", "class A")
            .build();
        let analyzer = KotlinAnalyzer::from_project(fixture.project().clone());
        let key: Arc<[String]> = vec!["A".to_string()].into();
        analyzer
            .dead_code_usage_edges
            .insert(key.clone(), Arc::new(UsageEdges::default()));

        brokk_bifrost_analysis::analyzer::test_support::assert_dead_code_cache_reset_after_update_paths(
            &analyzer,
            &key,
            |analyzer| &analyzer.dead_code_usage_edges,
            |analyzer| analyzer.update(&std::collections::BTreeSet::new()),
            |analyzer| analyzer.update_all(),
            |analyzer| analyzer.clone_with_project(fixture.project_dyn()),
        );
    }
}
