//! The analysis-side shim over [`brokk_bifrost_php`].
//!
//! PHP's language knowledge -- the declaration walk, namespace and `use`-alias
//! resolution, composer PSR-4 visibility, the structural spec, test detection,
//! clone normalization and the R1 free functions -- lives in the crate. What
//! stays here is the [`PhpAnalyzer`] struct with its one moka cache, one
//! `PoolSafeMemo` and the `Arc<PhpComposerAutoload>` it rebuilds when
//! `composer.json` changes, the `PhpAdapter` forwarding shell, the core
//! capability impls the crate resolves through, the `LanguageSupport` SPI block,
//! and the executable-semantics lowerer.

mod adapter;
mod clones;
pub mod dependency_discovery;
pub(crate) mod diagnostics;
mod external;
mod imports;
mod semantic;
mod source_artifact;
pub(crate) mod source_publication;
pub(crate) mod source_storage;
mod structural;
mod type_flow;

pub use dependency_discovery::{
    PHP_MAX_AUTOLOAD_RULES_PER_PACKAGE, resolve_php_semantic_pack_dependencies,
};
pub use external::{
    ComposerPackagePackProducer, ComposerPinnedAutoloadRule, PhpDeclarationStubPackProducer,
    PhpDependencyPackAdapter,
};
pub use semantic::php_declared_scalar_types;

use crate::analyzer::clone_detection::detect_language_structural_clone_smells;
use crate::analyzer::languages::{
    BoundedReceiverQuery, CandidateAugmentation, CandidateCtx, DeadCodeBulkEdges,
    DeadCodeBulkPreflight, DeadCodeBulkProof, DeadCodeRouting, DeadCodeSupport, EdgePassId,
    EdgeSiteScanCtx, EdgeWeightScanCtx, LanguageEdgePass, LanguageEdgeSites, LanguageEdgeWeights,
    LanguageSupport, StructuralReceiverResolver, build_fqn_bulk_edges, ready_preflight,
};
use crate::analyzer::store::LimitedQueryRows;
use crate::analyzer::usages::common::analyzed_files_for_language;
use crate::analyzer::usages::get_definition::{
    BoundedResolution, DefinitionLookupOutcome, resolve_php_bounded,
};
use crate::analyzer::usages::get_type::{TypeLookupOutcome, resolve_php_type_bounded};
use crate::analyzer::usages::php_graph::{
    PhpDeadCodeBulkEligibility, PhpUsageGraphStrategy, build_php_usage_edge_weights,
    build_php_usage_edges, build_rooted_php_usage_edges, dead_code_bulk_eligibility,
};
use crate::analyzer::usages::workspace_graph::UsageEcosystem;
use crate::analyzer::weighted_cache::{
    build_weighted_cache, weight_code_unit_set, weight_code_unit_vec_by_unit,
};
use crate::analyzer::{
    AnalyzerConfig, AnalyzerStoreContext, BuildProgress, CodeUnit, DescendantIndexScope,
    DescendantIndexVariant, DirectDescendantIndex, ForwardQueryProvider, IAnalyzer,
    ImportAnalysisProvider, KeyedPoolSafeMemo, Language, PoolSafeMemo, Project, ProjectFile, Range,
    SignatureMetadata, TestAssertionSmell, TestAssertionWeights, TestDetectionProvider,
    TreeSitterAnalyzer, TypeHierarchyProvider, WorkspaceAnalyzer, build_direct_descendant_index,
    descendants_from_variant_index, resolve_analyzer,
};
use crate::hash::{HashMap, HashSet};
use crate::{CloneSmell, CloneSmellWeights};
use moka::sync::Cache;
use std::collections::BTreeSet;
use std::sync::Arc;

pub(crate) use adapter::PhpAdapter;
pub(crate) use source_artifact::PHP_GLOBAL_NAMESPACE;

pub(crate) fn resolve_php_analyzer(workspace: &WorkspaceAnalyzer) -> Option<&PhpAnalyzer> {
    resolve_analyzer::<PhpAnalyzer>(workspace.analyzer())
}
// The parked bounded-definition route (`usages/get_definition/php.rs`) resolves
// these through the module, so the chain now runs crate -> shim -> parked file
// rather than the other way around.
pub(crate) use brokk_bifrost_php::aliases::{
    PhpDeclaredType, php_dynamic_type_keyword_node, resolve_php_constant_node,
    resolve_php_function_node, resolve_php_type_node, resolve_php_type_node_arms,
};
// PHP's four public alias names keep their historical `crate::analyzer::` paths
// even though they now live in `brokk-bifrost-php` -- the `brokk_bifrost_go::packages`
// idiom. `tests/suite_analyzers/php_analyzer_test.rs` imports them from there.
pub use brokk_bifrost_php::aliases::{
    PhpUseAliases, parse_php_use_aliases, parse_php_use_aliases_by_kind,
    parse_php_use_aliases_from_source, php_namespace_to_fq,
};
use brokk_bifrost_php::composer::PhpComposerAutoload;
use brokk_bifrost_php::graph::syntax::php_declaration_name_range;
use brokk_bifrost_php::graph_support::{
    php_import_alias_candidates, php_is_constructor, php_namespace_of_file,
    php_resolve_declared_supertype, php_use_aliases_by_kind_of, php_use_aliases_of,
};
pub use brokk_bifrost_php::structural::{PhpCallResultUseIndex, php_call_result_use};
use brokk_bifrost_php::test_detection::detect_php_test_assertion_smells;
use clones::build_php_clone_candidate_data;

#[derive(Clone)]
pub struct PhpAnalyzer {
    inner: TreeSitterAnalyzer<PhpAdapter>,
    memo_budget: u64,
    source_facts: Cache<
        (crate::analyzer::store::GenerationId, git2::Oid, ProjectFile),
        Arc<brokk_bifrost_php::source_facts::PhpFileSourceFacts>,
    >,
    direct_ancestors: Cache<CodeUnit, Arc<Vec<CodeUnit>>>,
    /// `PoolSafeMemo`, not `OnceLock`: this whole-workspace build is reached
    /// from rayon workers during cold scans, and a blocking `get_or_init` parks
    /// every one of them behind the single initializer for its full duration.
    /// Keyed by [`DescendantIndexVariant`]: a request that excluded test files
    /// gets an index that was never built over them (issue #1748). Two cells at
    /// most, because the exclusion verdict is a pure function of the analyzer
    /// and the file.
    direct_descendant_index: Arc<KeyedPoolSafeMemo<DescendantIndexVariant, DirectDescendantIndex>>,
    /// The declarations of other files that one file's persisted import names
    /// resolve to, keyed by file because the persisted names are. An entry
    /// depends on the whole workspace's declarations, not only on its own
    /// file's blob, so both cells are built fresh by `update` rather than
    /// invalidated per changed file -- the same lifetime `direct_ancestors`
    /// has.
    imported_code_units: Cache<ProjectFile, Arc<HashSet<CodeUnit>>>,
    /// Which files import each file, inverted from `imported_code_units` over
    /// the whole workspace in one pass.
    reverse_import_index: Arc<PoolSafeMemo<HashMap<ProjectFile, Arc<HashSet<ProjectFile>>>>>,
    composer_autoload: Arc<PhpComposerAutoload>,
}

crate::analyzer::impl_forward_query_provider!(PhpAnalyzer);

impl brokk_bifrost_php::source_facts::PhpSourceFactProvider for PhpAnalyzer {
    fn php_source_facts_while(
        &self,
        file: &ProjectFile,
        keep_going: &dyn Fn() -> bool,
    ) -> Option<Arc<brokk_bifrost_php::source_facts::PhpFileSourceFacts>> {
        self.inner
            .canonical_php_source_facts(file, &self.source_facts, keep_going)
    }
}

impl PhpAnalyzer {
    pub(crate) fn update_all_with_progress(
        &self,
        progress: Option<crate::analyzer::BuildProgress>,
    ) -> Self {
        Self::from_inner(
            self.inner.update_all_with_progress(progress),
            self.memo_budget,
        )
    }

    pub(crate) fn clone_with_project(&self, project: Arc<dyn Project>) -> Self {
        let mut clone = self.clone();
        clone.inner = clone.inner.clone_with_project(project);
        clone
    }

    pub fn new(project: Arc<dyn Project>) -> Self {
        Self::new_with_config(project, AnalyzerConfig::default())
    }

    pub fn new_with_config(project: Arc<dyn Project>, config: AnalyzerConfig) -> Self {
        TreeSitterAnalyzer::wrap_with_config(
            config,
            |config| TreeSitterAnalyzer::new_with_config(project, PhpAdapter, config),
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
                    PhpAdapter,
                    config,
                    store_context,
                    progress,
                )
            },
            Self::from_inner,
        )
    }

    fn from_inner(inner: TreeSitterAnalyzer<PhpAdapter>, memo_budget: u64) -> Self {
        let composer_autoload = Arc::new(PhpComposerAutoload::from_project(inner.project()));
        Self::from_inner_with_composer(inner, memo_budget, composer_autoload)
    }

    fn from_inner_with_composer(
        inner: TreeSitterAnalyzer<PhpAdapter>,
        memo_budget: u64,
        composer_autoload: Arc<PhpComposerAutoload>,
    ) -> Self {
        Self {
            inner,
            memo_budget,
            source_facts: build_weighted_cache(
                memo_budget / 8,
                |_key, facts: &Arc<brokk_bifrost_php::source_facts::PhpFileSourceFacts>| {
                    u32::try_from(facts.estimated_retained_bytes())
                        .unwrap_or(u32::MAX)
                        .max(1)
                },
            ),
            direct_ancestors: build_weighted_cache(memo_budget / 8, weight_code_unit_vec_by_unit),
            direct_descendant_index: Arc::new(KeyedPoolSafeMemo::new()),
            imported_code_units: build_weighted_cache(memo_budget / 8, weight_code_unit_set),
            reverse_import_index: Arc::new(PoolSafeMemo::new()),
            composer_autoload,
        }
    }

    pub fn from_project<P>(project: P) -> Self
    where
        P: Project + 'static,
    {
        Self::new(Arc::new(project))
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
        // PHP names are intrinsic to source contents, but the adapter predates
        // persisted FQN lookup keys. Query the bounded identifier index, then
        // retain only the exact analyzer identity; this is still an exact
        // lookup and never falls back to a same-name declaration.
        let mut candidates =
            self.inner
                .lookup_declarations_by_identifier_limited(identifier, limit, continue_query);
        candidates.rows.retain(|unit| unit.fq_name() == fqn);
        candidates
    }

    crate::analyzer::tree_sitter_analyzer::delegate_inner_methods! {
        pub(crate) fn direct_children_limited(
        &self,
        owner: &CodeUnit,
        limit: usize,
    ) -> LimitedQueryRows<CodeUnit>;
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

    pub(crate) fn ranges_limited(
        &self,
        code_unit: &CodeUnit,
        limit: usize,
    ) -> LimitedQueryRows<Range> {
        self.inner.ranges_limited(code_unit, limit)
    }

    pub fn is_constructor(
        &self,
        method: &CodeUnit,
        class_unit: &CodeUnit,
        package_name: &str,
    ) -> bool {
        php_is_constructor(method, class_unit, package_name)
    }

    pub fn namespace_of_file(&self, file: &ProjectFile) -> String {
        php_namespace_of_file(self, file)
    }

    pub fn use_aliases_of(&self, file: &ProjectFile) -> HashMap<String, String> {
        php_use_aliases_of(self, file)
    }

    pub fn use_aliases_by_kind_of(&self, file: &ProjectFile) -> PhpUseAliases {
        php_use_aliases_by_kind_of(self, file)
    }

    pub(crate) fn target_has_composer_autoload_visibility(&self, target: &CodeUnit) -> bool {
        self.composer_autoload.target_is_autoloaded(self, target)
    }
}

impl TestDetectionProvider for PhpAnalyzer {}

impl TypeHierarchyProvider for PhpAnalyzer {
    fn get_direct_ancestors(&self, code_unit: &CodeUnit) -> Vec<CodeUnit> {
        if let Some(cached) = self.direct_ancestors.get(code_unit) {
            return (*cached).clone();
        }

        let ancestors: Vec<_> = self
            .inner
            .raw_supertypes_of(code_unit)
            .iter()
            .filter_map(|raw| php_resolve_declared_supertype(self, code_unit, raw))
            .collect();
        self.direct_ancestors
            .insert(code_unit.clone(), Arc::new(ancestors.clone()));
        ancestors
    }

    fn get_direct_descendants(&self, code_unit: &CodeUnit) -> HashSet<CodeUnit> {
        crate::analyzer::whole_workspace_descendants(|scope| {
            self.get_direct_descendants_within(code_unit, scope)
        })
    }

    fn get_direct_descendants_within(
        &self,
        code_unit: &CodeUnit,
        scope: &DescendantIndexScope<'_>,
    ) -> Option<HashSet<CodeUnit>> {
        descendants_from_variant_index(&self.direct_descendant_index, scope, code_unit, || {
            build_direct_descendant_index(self, self, scope)
        })
    }
}

use crate::analyzer::CodeUnitIndex;

impl CodeUnitIndex for PhpAnalyzer {
    crate::analyzer::tree_sitter_analyzer::delegate_inner_methods! {
        /// Forwarded so the request-scoped memo on the inner analyzer answers
        /// (#2679); the trait default would rebuild uncached per call.
        fn class_range_index(
        &self,
        file: &ProjectFile,
    ) -> std::sync::Arc<brokk_bifrost_core::analyzer::usages::inverted_edges::ClassRangeIndex>;
    }

    fn enclosing_code_unit(&self, file: &ProjectFile, range: &Range) -> Option<CodeUnit> {
        self.inner.enclosing_code_unit(file, range)
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

    fn definitions(&self, fq_name: &str) -> Box<dyn Iterator<Item = CodeUnit> + '_> {
        self.inner.definitions(fq_name)
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

    crate::analyzer::tree_sitter_analyzer::delegate_inner_methods! {
        fn project(&self) -> &dyn Project;
    }

    crate::analyzer::tree_sitter_analyzer::delegate_inner_methods! {
        fn get_all_declarations(&self) -> Vec<CodeUnit>;
    }

    fn get_skeleton(&self, code_unit: &CodeUnit) -> Option<String> {
        let skeleton = self.inner.get_skeleton(code_unit)?;
        if code_unit.is_class() && self.inner.direct_children(code_unit).is_empty() {
            let trimmed = skeleton.trim();
            if trimmed.ends_with("{\n}") || trimmed.ends_with("{\r\n}") {
                let compact = trimmed.trim_end_matches('}').trim_end().to_string();
                return Some(format!("{compact} }}"));
            }
        }
        Some(skeleton)
    }

    crate::analyzer::tree_sitter_analyzer::delegate_inner_methods! {
        fn get_skeleton_header(&self, code_unit: &CodeUnit) -> Option<String>;
    }

    crate::analyzer::tree_sitter_analyzer::delegate_inner_methods! {
        fn get_source(&self, code_unit: &CodeUnit, include_comments: bool) -> Option<String>;
    }

    crate::analyzer::tree_sitter_analyzer::delegate_inner_methods! {
        fn get_sources(&self, code_unit: &CodeUnit, include_comments: bool) -> BTreeSet<String>;
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

impl IAnalyzer for PhpAnalyzer {
    crate::analyzer::tree_sitter_analyzer::delegate_inner_procedure_fact_methods!();

    crate::analyzer::i_analyzer::forward_relational_definition_batch!();

    crate::analyzer::i_analyzer::forward_file_identity_invalidation!();

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
        fn import_statements(&self, file: &ProjectFile) -> Vec<String>;
    }

    crate::analyzer::tree_sitter_analyzer::delegate_inner_methods! {
        fn compute_cognitive_complexities(&self, file: &ProjectFile) -> Vec<(CodeUnit, u32)>;
    }

    fn update(&self, changed_files: &BTreeSet<ProjectFile>) -> Self {
        let inner = self.inner.update(changed_files);
        let composer_autoload = if changed_files
            .iter()
            .any(PhpComposerAutoload::manifest_changed)
        {
            Arc::new(PhpComposerAutoload::from_project(inner.project()))
        } else {
            self.composer_autoload.clone()
        };
        Self::from_inner_with_composer(inner, self.memo_budget, composer_autoload)
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
        // The collector now states its own proof for every reference, so the
        // blanket workspace-local wrapper would overstate what it checked.
        diagnostics::collect_php_semantic_diagnostics(self, file, source)
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

    fn type_hierarchy_provider(&self) -> Option<&dyn TypeHierarchyProvider> {
        Some(self)
    }

    fn import_analysis_provider(&self) -> Option<&dyn ImportAnalysisProvider> {
        Some(self)
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
        crate::analyzer::test_assertion_smells_for_file(self, file, Language::Php, |source| {
            detect_php_test_assertion_smells(file, source, &weights)
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
        detect_language_structural_clone_smells(self, files, weights, Language::Php, |code_unit| {
            build_php_clone_candidate_data(self, code_unit, weights)
        })
    }

    fn test_detection_provider(&self) -> Option<&dyn TestDetectionProvider> {
        Some(self)
    }
}

#[cfg(any(test, feature = "test-support"))]
impl crate::analyzer::AnalyzerTestHooks for PhpAnalyzer {
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
}

static PHP_USAGE_STRATEGY: PhpUsageGraphStrategy = PhpUsageGraphStrategy::new();

pub(crate) struct PhpSupport;

impl LanguageSupport for PhpSupport {
    fn language(&self) -> Language {
        Language::Php
    }

    fn procedure_syntax_roles(&self) -> Option<crate::analyzer::languages::ProcedureSyntaxRoles> {
        Some(semantic::PROCEDURE_SYNTAX_ROLES)
    }

    fn declaration_name_range(&self, node: tree_sitter::Node<'_>, _source: &str) -> Range {
        php_declaration_name_range(node)
    }

    fn signature_metadata_limited(
        &self,
        analyzer: &dyn IAnalyzer,
        unit: &CodeUnit,
        limit: usize,
    ) -> Option<LimitedQueryRows<SignatureMetadata>> {
        resolve_analyzer::<PhpAnalyzer>(analyzer)
            .map(|php| php.signature_metadata_limited(unit, limit))
    }

    fn signatures_limited(
        &self,
        analyzer: &dyn IAnalyzer,
        unit: &CodeUnit,
        limit: usize,
    ) -> Option<LimitedQueryRows<String>> {
        resolve_analyzer::<PhpAnalyzer>(analyzer).map(|php| php.signatures_limited(unit, limit))
    }

    fn declaration_ranges_limited(
        &self,
        analyzer: &dyn IAnalyzer,
        unit: &CodeUnit,
        limit: usize,
    ) -> Option<LimitedQueryRows<Range>> {
        resolve_analyzer::<PhpAnalyzer>(analyzer).map(|php| php.ranges_limited(unit, limit))
    }

    fn forward_query_provider<'a>(
        &self,
        analyzer: &'a dyn IAnalyzer,
    ) -> Option<&'a dyn ForwardQueryProvider> {
        crate::analyzer::forward_query_provider::<PhpAnalyzer>(analyzer)
    }

    fn ecosystem(&self) -> UsageEcosystem {
        UsageEcosystem::Php
    }

    fn reference_usage_strategy(&self) -> &'static dyn crate::analyzer::usages::GraphUsageAnalyzer {
        &PHP_USAGE_STRATEGY
    }

    fn reference_graph_backend(&self) -> crate::analyzer::languages::LanguageGraphBackend {
        crate::analyzer::languages::LanguageGraphBackend::Legacy(&PhpEdgePass)
    }

    fn dead_code(&self) -> DeadCodeSupport {
        DeadCodeSupport {
            strategy: Some(&PHP_USAGE_STRATEGY),
            bulk: Some(&PhpDeadCodeBulk),
        }
    }

    fn structural_receiver(&self) -> Option<&'static dyn StructuralReceiverResolver> {
        Some(&PhpSupport)
    }

    fn type_flow_adapter(&self) -> Option<&'static dyn crate::analyzer::semantic::TypeFlowAdapter> {
        Some(&type_flow::PhpTypeFlowAdapter)
    }

    /// Both expansions are supplemental. Composer autoload visibility means any analyzed
    /// PHP file may reference the target, so the expansion is the whole language's file
    /// set -- accurate but unbounded, and worth dropping the moment a budget bites rather
    /// than displacing the import-graph candidates that are far likelier to hold a usage.
    fn candidate_augmentation(&self, ctx: &CandidateCtx<'_>) -> Option<CandidateAugmentation> {
        let php = resolve_analyzer::<PhpAnalyzer>(ctx.analyzer)?;
        let analyzed_php_files = || analyzed_files_for_language(ctx.analyzer, Language::Php);
        let mut files = HashSet::default();
        if php.target_has_composer_autoload_visibility(ctx.target) {
            files.extend(analyzed_php_files());
        }
        files.extend(php_import_alias_candidates(
            ctx.target,
            ctx.analyzer,
            ctx.analyzer.type_hierarchy_provider(),
            php,
            &analyzed_php_files,
        ));
        Some(CandidateAugmentation::supplemental(files))
    }

    fn parser_language(&self, _flavor: crate::analyzer::ParserFlavor) -> tree_sitter::Language {
        tree_sitter_php::LANGUAGE_PHP.into()
    }

    fn structural_spec(&self) -> &'static dyn crate::analyzer::structural::StructuralSpec {
        &brokk_bifrost_php::structural::PHP_STRUCTURAL_SPEC
    }

    fn highlight_query(&self) -> Option<&'static str> {
        Some(tree_sitter_php::HIGHLIGHTS_QUERY)
    }
}

struct PhpEdgePass;

impl LanguageEdgePass for PhpEdgePass {
    fn id(&self) -> EdgePassId {
        EdgePassId::Php
    }

    fn edge_sites(&self, ctx: &EdgeSiteScanCtx<'_>) -> Option<LanguageEdgeSites> {
        build_rooted_php_usage_edges(ctx.analyzer, ctx.fqns, ctx.keep_file)
            .map(LanguageEdgeSites::Fqn)
    }

    fn edge_weights(&self, ctx: &EdgeWeightScanCtx<'_>) -> Option<LanguageEdgeWeights> {
        build_php_usage_edge_weights(ctx.analyzer, ctx.fqns, ctx.keep_file)
            .map(LanguageEdgeWeights::Fqn)
    }
}

impl StructuralReceiverResolver for PhpSupport {
    fn resolve_type_bounded(
        &self,
        query: BoundedReceiverQuery<'_>,
    ) -> BoundedResolution<TypeLookupOutcome> {
        resolve_php_type_bounded(
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
        resolve_php_bounded(
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

struct PhpDeadCodeBulk;

impl DeadCodeBulkProof for PhpDeadCodeBulk {
    fn id(&self) -> EdgePassId {
        EdgePassId::Php
    }

    fn needs_precise_scan(&self, routing: DeadCodeRouting<'_>) -> bool {
        matches!(
            dead_code_bulk_eligibility(routing.analyzer, routing.candidate),
            PhpDeadCodeBulkEligibility::NeedsPrecise
        )
    }

    fn preflight(&self, analyzer: &dyn IAnalyzer) -> DeadCodeBulkPreflight {
        ready_preflight(analyzer, Language::Php, "PHP")
    }

    fn build(
        &self,
        analyzer: &dyn IAnalyzer,
        candidates: &[CodeUnit],
    ) -> Option<DeadCodeBulkEdges> {
        build_fqn_bulk_edges(analyzer, Language::Php, candidates, |analyzer, nodes| {
            build_php_usage_edges(analyzer, nodes, |_| true)
        })
    }
}

#[cfg(test)]
mod source_fact_tests;
