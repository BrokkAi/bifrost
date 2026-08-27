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
//! (#1238); the resolver itself lives in
//! `crate::analyzer::usages::get_definition::kotlin` because it is a consumer
//! of this module's index rather than part of it.
//!
//! Structural CodeQuery/RQL is live too (#1240): [`structural`] supplies the
//! [`crate::analyzer::structural::StructuralSpec`] the shared engine needs, so
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

mod adapter;
mod clones;
pub(crate) mod diagnostics;
mod hierarchy;
pub(crate) mod imports;
pub(crate) mod language;
mod semantic;
mod structural;
pub(crate) mod types;

use crate::analyzer::Range;
use crate::analyzer::store::LimitedQueryRows;
use crate::analyzer::structural::BoundaryStatus;
use brokk_bifrost_core::analyzer::query_token::QueryToken;
use brokk_bifrost_jvm::kotlin::graph_support::KotlinSource;
use brokk_bifrost_jvm::kotlin::imports::build_kotlin_top_level_declarations_by_package;
use brokk_bifrost_jvm::kotlin::syntax;

use crate::analyzer::clone_detection::detect_language_structural_clone_smells;
use crate::analyzer::common::language_for_file as file_language;
use crate::analyzer::jvm::dependency_discovery::is_jvm_dependency_input;
use crate::analyzer::jvm::external::{JvmExternalDeclarationIndex, JvmExternalDeclarations};
use crate::analyzer::jvm::retained_external_index_state;
use crate::analyzer::languages::{
    BoundedReceiverQuery, DeadCodeBulkEdges, DeadCodeBulkPreflight, DeadCodeBulkProof,
    DeadCodeRouting, DeadCodeSupport, EdgePassId, EdgeSiteScanCtx, EdgeWeightScanCtx,
    LanguageEdgePass, LanguageEdgeSites, LanguageEdgeWeights, LanguageSupport,
    StructuralReceiverResolver, analyzable_file_count, candidate_fqns,
    fqn_has_multiple_function_definitions,
};
use crate::analyzer::pool_memo::{KeyedPoolSafeMemo, PoolSafeMemo};
use crate::analyzer::usages::get_definition::{
    BoundedResolution, DefinitionLookupOutcome, resolve_kotlin_bounded,
};
use crate::analyzer::usages::get_type::{TypeLookupOutcome, resolve_kotlin_type_bounded};
use crate::analyzer::usages::kotlin_graph::{
    KotlinUsageGraphStrategy, build_inbound_kotlin_usage_edges, build_kotlin_usage_edge_weights,
};
use crate::analyzer::usages::workspace_graph::UsageEcosystem;
use crate::analyzer::weighted_cache::{
    build_weighted_cache, weight_code_unit_set, weight_code_unit_vec_by_unit,
    weight_project_file_set,
};
use crate::analyzer::{
    AnalyzerConfig, AnalyzerStoreContext, BuildProgress, CloneSmell, CloneSmellWeights, CodeUnit,
    ForwardQueryProvider, IAnalyzer, ImportAnalysisProvider, JvmAnalyzerConfig, Language, Project,
    ProjectFile, SignatureMetadata, TestAssertionSmell, TestAssertionWeights,
    TestDetectionProvider, TreeSitterAnalyzer, TypeAliasProvider, TypeHierarchyProvider,
    resolve_analyzer,
};
use crate::hash::{HashMap, HashSet};
use brokk_bifrost_jvm::kotlin::test_detection::detect_kotlin_test_assertion_smells;
use brokk_bifrost_jvm::proof::JvmRetainedExternalIndex;
use moka::sync::Cache;
use std::collections::BTreeSet;
use std::sync::{Arc, OnceLock};
use tree_sitter::Node;

use crate::analyzer::{AnalyzerQueryScope, QueryScope};
pub(crate) use adapter::KotlinAdapter;
use clones::build_kotlin_clone_candidate_data;

#[derive(Clone)]
pub struct KotlinAnalyzer {
    inner: TreeSitterAnalyzer<KotlinAdapter>,
    /// Kotlin's share of the JVM dependency realm: the same jar-backed index
    /// Java and Scala consult, built from the same discovered Maven/Gradle
    /// artifacts. Built lazily because opening jars is expensive and many
    /// workspaces never ask a question that needs it.
    jvm_config: JvmAnalyzerConfig,
    external_index: Arc<OnceLock<JvmExternalDeclarationIndex>>,
    memo_budget: u64,
    imported_code_units: Cache<ProjectFile, Arc<HashSet<CodeUnit>>>,
    /// Import and hierarchy answers computed with the whole JVM source realm
    /// in view. Kept apart from the Kotlin-only caches above because they
    /// answer a strictly wider question: serving one for the other would
    /// silently drop, or invent, cross-language results.
    realm_imported_code_units: Cache<ProjectFile, Arc<HashSet<CodeUnit>>>,
    referencing_files: Cache<ProjectFile, Arc<HashSet<ProjectFile>>>,
    reverse_import_index: Arc<PoolSafeMemo<HashMap<ProjectFile, Arc<HashSet<ProjectFile>>>>>,
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
            crate::analyzer::DescendantIndexVariant,
            crate::analyzer::DirectDescendantIndex,
        >,
    >,
    realm_direct_descendant_index: Arc<
        KeyedPoolSafeMemo<
            crate::analyzer::DescendantIndexVariant,
            crate::analyzer::DirectDescendantIndex,
        >,
    >,
}

crate::analyzer::impl_forward_query_provider!(KotlinAnalyzer);

impl KotlinAnalyzer {
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
        source_mode: crate::analyzer::BulkFileStateSource,
    ) -> crate::hash::HashMap<ProjectFile, crate::analyzer::tree_sitter_analyzer::FileState> {
        self.inner.bulk_file_states(files, source_mode)
    }

    pub(crate) fn raw_supertypes_limited(
        &self,
        code_unit: &CodeUnit,
        limit: usize,
    ) -> crate::analyzer::store::LimitedQueryRows<String> {
        self.inner.raw_supertypes_limited(code_unit, limit)
    }

    #[doc(hidden)]
    pub fn reset_full_hydration_count_for_test(&self) {
        self.inner.reset_full_hydration_count_for_test();
    }

    #[doc(hidden)]
    pub fn full_hydration_count_for_test(&self) -> usize {
        self.inner.full_hydration_count_for_test()
    }

    #[doc(hidden)]
    pub fn bulk_hydration_count_for_test(&self) -> usize {
        self.inner.bulk_hydration_count_for_test()
    }

    pub fn new_with_config(project: Arc<dyn Project>, config: AnalyzerConfig) -> Self {
        let memo_budget = config.memo_cache_budget_bytes();
        let jvm_config = config.jvm.clone();
        let inner = TreeSitterAnalyzer::new_with_config(project, KotlinAdapter, config);
        Self::from_inner(inner, memo_budget, jvm_config)
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
            same_package_reference_index: Arc::new(PoolSafeMemo::new()),
            top_level_declarations_by_package: Arc::new(OnceLock::new()),
            direct_ancestors: build_weighted_cache(memo_budget / 16, weight_code_unit_vec_by_unit),
            realm_direct_ancestors: build_weighted_cache(
                memo_budget / 16,
                weight_code_unit_vec_by_unit,
            ),
            direct_descendant_index: Arc::new(KeyedPoolSafeMemo::new()),
            realm_direct_descendant_index: Arc::new(KeyedPoolSafeMemo::new()),
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
    ) -> Result<Self, crate::analyzer::store::StoreError> {
        let memo_budget = config.memo_cache_budget_bytes();
        let jvm_config = config.jvm.clone();
        let inner = TreeSitterAnalyzer::new_with_config_storage_context_and_progress(
            project,
            KotlinAdapter,
            config,
            store_context,
            progress,
        )?;
        Ok(Self::from_inner(inner, memo_budget, jvm_config))
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

    /// Kotlin's view of the shared JVM dependency realm.
    pub(crate) fn external_declaration_index(&self) -> &JvmExternalDeclarationIndex {
        self.external_index.get_or_init(|| {
            JvmExternalDeclarationIndex::build_for_project(&self.jvm_config, self.inner.project())
        })
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
        packs: Option<Arc<crate::analyzer::semantic_model::SemanticModelOverlay>>,
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
    pub(crate) fn external_boundary_evidence(
        &self,
        token: QueryToken<'_>,
        packs: Option<Arc<crate::analyzer::semantic_model::SemanticModelOverlay>>,
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
        match resolve_kotlin_type_name(name, &scope, declares) {
            KotlinTypeName::Resolved(fqn) => {
                return (BoundaryStatus::ExternalIndexed, Some(fqn));
            }
            // Two star imports both name an indexed external type: the name is
            // certainly indexed, but no single target can be reported.
            KotlinTypeName::Ambiguous => return (BoundaryStatus::ExternalIndexed, None),
            KotlinTypeName::Unresolved => {}
        }
        // A member spelling leaves the workspace exactly as its owner type
        // does, so the member tier runs where the type tier found nothing
        // (#1900). A member the surface does not declare changes nothing.
        // One ladder answers here and in the resolver's own boundary gate, so
        // a trace and a definition cannot disagree about a spelling (#2287).
        if let Some(member) = self.resolve_member_name_with_external(token, packs, file, name) {
            return (
                BoundaryStatus::ExternalIndexed,
                Some(member.fqn().to_owned()),
            );
        }
        if self
            .external_declaration_index()
            .production_diagnostic_count()
            > 0
        {
            return (BoundaryStatus::ExternalDeclaredUnindexed, None);
        }
        (BoundaryStatus::ExternalUnknown, None)
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
        packs: Option<Arc<crate::analyzer::semantic_model::SemanticModelOverlay>>,
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
        read: &mut dyn FnMut(&dyn crate::analyzer::BoundedDefinitionLookup),
    ) {
        let lookup = crate::analyzer::AnalyzerDefinitionLookup::new(self, Language::Kotlin);
        read(&lookup);
    }

    fn type_identifiers_of(&self, file: &ProjectFile) -> Option<HashSet<String>> {
        self.inner.type_identifiers_of(file)
    }

    fn raw_supertypes_of(&self, code_unit: &CodeUnit) -> Vec<String> {
        self.inner.raw_supertypes_of(code_unit)
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
        self.external_declaration_index()
            .resolve_qualified_name(fqn, access_package)
            .is_some()
    }

    fn retained_external_index(&self) -> JvmRetainedExternalIndex {
        retained_external_index_state(self.external_index.get())
    }

    fn retained_external_qualified_name_exists(&self, fqn: &str, access_package: &str) -> bool {
        self.external_index.get().is_some_and(|external| {
            external
                .resolve_qualified_name(fqn, access_package)
                .is_some()
        })
    }
}

use crate::analyzer::CodeUnitIndex;

impl CodeUnitIndex for KotlinAnalyzer {
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
        let mut projection = (*self.inner.summary_file_projection(file)?).clone();
        for children in projection.children.values_mut() {
            children.retain(|child| !child.is_synthetic());
        }
        Some(Arc::new(projection))
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
        self.inner
            .direct_children(code_unit)
            .into_iter()
            .filter(|child| !child.is_synthetic())
            .collect()
    }

    fn parent_of(&self, code_unit: &CodeUnit) -> Option<CodeUnit> {
        CodeUnitIndex::parent_of(&self.inner, code_unit)
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
        let rendered = crate::analyzer::common::render_skeleton(self, code_unit, false);
        (!rendered.is_empty()).then(|| rendered.trim_end().to_string())
    }

    fn get_skeleton_header(&self, code_unit: &CodeUnit) -> Option<String> {
        let rendered = crate::analyzer::common::render_skeleton(self, code_unit, true);
        (!rendered.is_empty()).then(|| rendered.trim_end().to_string())
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

impl IAnalyzer for KotlinAnalyzer {
    crate::analyzer::i_analyzer::forward_relational_definition_batch!();

    fn invalidate_cached_file_identities(&self) {
        self.inner.invalidate_cached_file_identities();
    }

    fn working_tree_identity(&self) -> Option<std::sync::Arc<crate::gitblob::WorkingTreeIdentity>> {
        self.inner.working_tree_identity()
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

    fn import_statements(&self, file: &ProjectFile) -> Vec<String> {
        self.inner.import_statements(file)
    }

    fn compute_cognitive_complexities(&self, file: &ProjectFile) -> Vec<(CodeUnit, u32)> {
        self.inner.compute_cognitive_complexities(file)
    }

    fn semantic_diagnostics(
        &self,
        file: &ProjectFile,
        source: &str,
    ) -> crate::analyzer::SemanticDiagnosticReport {
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

    fn update(&self, changed_files: &BTreeSet<ProjectFile>) -> Self {
        // Every import- and package-derived index is rebuilt from the new
        // generation: an edit anywhere can add, remove, or rename a
        // declaration that some other file's import resolves to.
        let mut updated = Self::from_inner(
            self.inner.update(changed_files),
            self.memo_budget,
            self.jvm_config.clone(),
        );
        // A touched build manifest can add or drop dependencies, so the
        // jar-backed index is discarded and rebuilt on demand; every other
        // edit leaves the classpath alone and the existing index stands.
        if !changed_files.iter().any(is_jvm_dependency_input) {
            updated.external_index = Arc::clone(&self.external_index);
        }
        updated
    }

    fn update_all(&self) -> Self {
        Self::from_inner(
            self.inner.update_all(),
            self.memo_budget,
            self.jvm_config.clone(),
        )
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
        self.inner.contains_tests(file)
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
        if file_language(file) != Language::Kotlin || !self.contains_tests(file) {
            return Vec::new();
        }
        let Ok(source) = self.inner.project().read_source(file) else {
            return Vec::new();
        };
        detect_kotlin_test_assertion_smells(self, file, &source, &weights)
    }

    fn test_detection_provider(&self) -> Option<&dyn TestDetectionProvider> {
        Some(self)
    }
}

#[cfg(any(test, feature = "test-support"))]
impl crate::analyzer::AnalyzerTestHooks for KotlinAnalyzer {
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

impl TestDetectionProvider for KotlinAnalyzer {}

static KOTLIN_USAGE_STRATEGY: KotlinUsageGraphStrategy = KotlinUsageGraphStrategy::new();

pub(crate) struct KotlinSupport;

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
        DeadCodeBulkPreflight::Ready {
            label: "Kotlin",
            files: analyzable_file_count(analyzer, Language::Kotlin),
        }
    }

    fn build(
        &self,
        analyzer: &dyn IAnalyzer,
        candidates: &[CodeUnit],
    ) -> Option<DeadCodeBulkEdges> {
        let scope = AnalyzerQueryScope::new(analyzer);
        let callees = candidate_fqns(candidates);
        build_inbound_kotlin_usage_edges(analyzer, scope.token(), &callees)
            .map(|edges| DeadCodeBulkEdges::Fqn(Arc::new(edges)))
    }
}

impl LanguageSupport for KotlinSupport {
    fn language(&self) -> Language {
        Language::Kotlin
    }

    /// Kotlin's grammar names neither the callee of a call nor the member of a
    /// navigation, so both are read through the positional readers the Kotlin adapters
    /// already use.
    fn call_callee_node<'t>(&self, call: Node<'t>) -> Option<Node<'t>> {
        syntax::kotlin_callee(call)
    }

    /// The argument list is `value_arguments`, which an ordinary call nests one level
    /// down inside `call_suffix`.
    fn call_argument_nodes<'t>(&self, call: Node<'t>) -> Option<Vec<Node<'t>>> {
        Some(syntax::kotlin_value_arguments(call).into_iter().collect())
    }

    fn factory_name_node<'t>(&self, call: Node<'t>) -> Option<Node<'t>> {
        if call.kind() != "call_expression" {
            return None;
        }
        let callee = syntax::kotlin_callee(call)?;
        match callee.kind() {
            "navigation_expression" => syntax::kotlin_navigation_member(callee),
            "simple_identifier" => Some(callee),
            _ => None,
        }
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
        resolve_analyzer::<KotlinAnalyzer>(analyzer)
            .map(|kotlin| kotlin.ranges_limited(unit, limit))
    }

    fn forward_query_provider<'a>(
        &self,
        analyzer: &'a dyn IAnalyzer,
    ) -> Option<&'a dyn ForwardQueryProvider> {
        resolve_analyzer::<KotlinAnalyzer>(analyzer).map(|value| value as _)
    }

    fn ecosystem(&self) -> UsageEcosystem {
        UsageEcosystem::Jvm
    }

    fn reference_plugin(&self) -> crate::analyzer::languages::ReferenceLanguagePlugin {
        crate::analyzer::languages::ReferenceLanguagePlugin::new(
            &KOTLIN_USAGE_STRATEGY,
            &KotlinEdgePass,
        )
    }

    fn dead_code(&self) -> DeadCodeSupport {
        DeadCodeSupport {
            strategy: Some(&KOTLIN_USAGE_STRATEGY),
            bulk: Some(&KOTLIN_DEAD_CODE_BULK),
        }
    }

    fn structural_receiver(&self) -> Option<&'static dyn StructuralReceiverResolver> {
        Some(&KotlinSupport)
    }

    fn parser_language(&self, _flavor: crate::analyzer::ParserFlavor) -> tree_sitter::Language {
        language::LANGUAGE.into()
    }

    fn structural_spec(&self) -> &'static dyn crate::analyzer::structural::StructuralSpec {
        &brokk_bifrost_jvm::kotlin::structural::KOTLIN_STRUCTURAL_SPEC
    }

    fn highlight_query(&self) -> Option<&'static str> {
        Some(brokk_bifrost_jvm::queries::KOTLIN_HIGHLIGHTS_QUERY)
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
        let scope = AnalyzerQueryScope::new(ctx.analyzer);
        let token = scope.token();
        crate::analyzer::usages::kotlin_graph::build_rooted_kotlin_usage_edges(
            ctx.analyzer,
            token,
            ctx.fqns,
            ctx.keep_file,
        )
        .map(LanguageEdgeSites::Fqn)
    }

    fn edge_weights(&self, ctx: &EdgeWeightScanCtx<'_>) -> Option<LanguageEdgeWeights> {
        let scope = AnalyzerQueryScope::new(ctx.analyzer);
        let token = scope.token();
        build_kotlin_usage_edge_weights(ctx.analyzer, token, ctx.fqns, ctx.keep_file)
            .map(LanguageEdgeWeights::Fqn)
    }
}

impl StructuralReceiverResolver for KotlinSupport {
    fn resolve_type_bounded(
        &self,
        query: BoundedReceiverQuery<'_>,
    ) -> BoundedResolution<TypeLookupOutcome> {
        let scope = AnalyzerQueryScope::new(query.analyzer);
        resolve_kotlin_type_bounded(
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

    fn resolve_definition_bounded(
        &self,
        query: BoundedReceiverQuery<'_>,
    ) -> BoundedResolution<DefinitionLookupOutcome> {
        resolve_kotlin_bounded(
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
