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
mod diagnostics;
mod semantic;
mod structural;

use crate::analyzer::clone_detection::{
    CloneCandidateProfile, detect_structural_clone_smells, refine_clone_similarity_with_ast,
};
use crate::analyzer::common::language_for_file as file_language;
use crate::analyzer::languages::{
    BoundedReceiverQuery, CandidateAugmentation, CandidateCtx, DeadCodeBulkEdges,
    DeadCodeBulkPreflight, DeadCodeBulkProof, DeadCodeRouting, DeadCodeSupport, EdgePassId,
    EdgeSiteScanCtx, EdgeWeightScanCtx, LanguageEdgePass, LanguageEdgeSites, LanguageEdgeWeights,
    LanguageSupport, StructuralReceiverResolver, analyzable_file_count, fqn_bulk_nodes,
};
use crate::analyzer::store::LimitedQueryRows;
use crate::analyzer::usages::GraphUsageAnalyzer;
use crate::analyzer::usages::common::analyzed_files_for_language;
use crate::analyzer::usages::get_definition::{
    BoundedResolution, DefinitionLookupOutcome, resolve_php_bounded,
};
use crate::analyzer::usages::get_type::{TypeLookupOutcome, resolve_php_type_bounded};
use crate::analyzer::usages::php_graph::{
    PhpDeadCodeBulkEligibility, PhpUsageGraphStrategy, build_php_usage_edge_weights,
    build_php_usage_edges, dead_code_bulk_eligibility,
};
use crate::analyzer::usages::workspace_graph::UsageEcosystem;
use crate::analyzer::weighted_cache::{build_weighted_cache, weight_code_unit_vec_by_unit};
use crate::analyzer::{
    AnalyzerConfig, AnalyzerStoreContext, BuildProgress, CodeUnit, DirectDescendantIndex,
    ForwardQueryProvider, IAnalyzer, Language, PoolSafeMemo, Project, ProjectFile, Range,
    SignatureMetadata, TestAssertionSmell, TestAssertionWeights, TestDetectionProvider,
    TreeSitterAnalyzer, TypeHierarchyProvider, UsageFactsIndex, build_direct_descendant_index,
    resolve_analyzer,
};
use crate::hash::{HashMap, HashSet};
use crate::{CloneSmell, CloneSmellWeights};
use moka::sync::Cache;
use std::collections::BTreeSet;
use std::sync::Arc;

pub(crate) use adapter::PhpAdapter;
// The parked bounded-definition route (`usages/get_definition/php.rs`) resolves
// these through the module, so the chain now runs crate -> shim -> parked file
// rather than the other way around.
pub(crate) use brokk_bifrost_php::aliases::{
    php_file_context_from_tree_at, resolve_php_constant_node, resolve_php_function_node,
    resolve_php_type_node,
};
// PHP's four public alias names keep their historical `crate::analyzer::` paths
// even though they now live in `brokk-bifrost-php` -- the `brokk_bifrost_go::packages`
// idiom. `tests/suite_analyzers/php_analyzer_test.rs` imports them from there.
pub use brokk_bifrost_php::aliases::{
    PhpUseAliases, parse_php_use_aliases, parse_php_use_aliases_by_kind,
    parse_php_use_aliases_from_source, php_namespace_to_fq,
};
use brokk_bifrost_php::composer::PhpComposerAutoload;
use brokk_bifrost_php::graph_support::{
    php_import_alias_candidates, php_is_constructor, php_namespace_of_file,
    php_resolve_declared_supertype, php_use_aliases_by_kind_of, php_use_aliases_of,
};
use brokk_bifrost_php::test_detection::detect_php_test_assertion_smells;
use clones::build_php_clone_candidate_data;

#[derive(Clone)]
pub struct PhpAnalyzer {
    inner: TreeSitterAnalyzer<PhpAdapter>,
    memo_budget: u64,
    direct_ancestors: Cache<CodeUnit, Arc<Vec<CodeUnit>>>,
    /// `PoolSafeMemo`, not `OnceLock`: this whole-workspace build is reached
    /// from rayon workers during cold scans, and a blocking `get_or_init` parks
    /// every one of them behind the single initializer for its full duration.
    direct_descendant_index: Arc<PoolSafeMemo<DirectDescendantIndex>>,
    composer_autoload: Arc<PhpComposerAutoload>,
}

crate::analyzer::impl_forward_query_provider!(PhpAnalyzer);

impl PhpAnalyzer {
    pub(crate) fn clone_with_project(&self, project: Arc<dyn Project>) -> Self {
        let mut clone = self.clone();
        clone.inner = clone.inner.clone_with_project(project);
        clone
    }

    pub fn new(project: Arc<dyn Project>) -> Self {
        Self::new_with_config(project, AnalyzerConfig::default())
    }

    pub fn new_with_config(project: Arc<dyn Project>, config: AnalyzerConfig) -> Self {
        let memo_budget = config.memo_cache_budget_bytes();
        let inner = TreeSitterAnalyzer::new_with_config(project, PhpAdapter, config);
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
            PhpAdapter,
            config,
            store_context,
            progress,
        )?;
        Ok(Self::from_inner(inner, memo_budget))
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
            direct_ancestors: build_weighted_cache(memo_budget / 8, weight_code_unit_vec_by_unit),
            direct_descendant_index: Arc::new(PoolSafeMemo::new()),
            composer_autoload,
        }
    }

    pub fn from_project<P>(project: P) -> Self
    where
        P: Project + 'static,
    {
        Self::new(Arc::new(project))
    }

    pub(crate) fn prepared_syntax_limited_cancellable(
        &self,
        file: &ProjectFile,
        max_source_bytes: usize,
        cancellation: Option<&crate::cancellation::CancellationToken>,
    ) -> crate::analyzer::tree_sitter_analyzer::PreparedSyntaxLimitedOutcome {
        self.inner
            .prepared_syntax_limited_cancellable(file, max_source_bytes, cancellation)
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

    pub(crate) fn direct_children_limited(
        &self,
        owner: &CodeUnit,
        limit: usize,
    ) -> LimitedQueryRows<CodeUnit> {
        self.inner.direct_children_limited(owner, limit)
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
        // The builder itself is serial, so the same closure serves both memo
        // arms; the memo's value here is the non-blocking claim protocol.
        self.direct_descendant_index
            .get_or_build(
                || build_direct_descendant_index(self, self),
                || build_direct_descendant_index(self, self),
            )
            .descendants(code_unit)
    }
}

use crate::analyzer::CodeUnitIndex;

impl CodeUnitIndex for PhpAnalyzer {
    fn enclosing_code_unit(&self, file: &ProjectFile, range: &Range) -> Option<CodeUnit> {
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
}

impl IAnalyzer for PhpAnalyzer {
    fn invalidate_cached_file_identities(&self) {
        self.inner.invalidate_cached_file_identities();
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

    fn usage_facts_index(&self) -> &UsageFactsIndex {
        self.inner.usage_facts_index()
    }

    fn structural_search_providers(
        &self,
    ) -> Vec<&dyn crate::analyzer::structural::StructuralSearchProvider> {
        self.inner.structural_search_providers()
    }

    fn snapshot_caches(&self) -> Option<&crate::analyzer::AnalyzerSnapshotCaches> {
        Some(self.inner.snapshot_caches())
    }

    fn import_statements(&self, file: &ProjectFile) -> Vec<String> {
        self.inner.import_statements(file)
    }

    fn compute_cognitive_complexities(&self, file: &ProjectFile) -> Vec<(CodeUnit, u32)> {
        self.inner.compute_cognitive_complexities(file)
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
        Self::from_inner(self.inner.update_all(), self.memo_budget)
    }

    fn parse_errors(&self, file: &ProjectFile) -> Option<Vec<crate::analyzer::ParseError>> {
        self.inner.parse_errors(file)
    }

    fn semantic_diagnostics(
        &self,
        file: &ProjectFile,
        source: &str,
    ) -> crate::analyzer::SemanticDiagnosticReport {
        let diagnostics = diagnostics::collect_php_semantic_diagnostics(self, file, source)
            .into_iter()
            .map(Into::into)
            .collect();
        crate::analyzer::SemanticDiagnosticReport::from_workspace_absences(file, diagnostics)
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

    fn type_hierarchy_provider(&self) -> Option<&dyn TypeHierarchyProvider> {
        Some(self)
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
        if !self.contains_tests(file) || file_language(file) != Language::Php {
            return Vec::new();
        }
        let Ok(source) = self.inner.project().read_source(file) else {
            return Vec::new();
        };
        detect_php_test_assertion_smells(file, &source, &weights)
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
            .filter(|file| file_language(file) == Language::Php)
            .cloned()
            .collect();
        if requested_files.is_empty() {
            return Vec::new();
        }

        let all_candidates: Vec<CloneCandidateProfile> = self
            .get_all_declarations()
            .into_iter()
            .filter(|code_unit| {
                code_unit.is_function() && file_language(code_unit.source()) == Language::Php
            })
            .filter_map(|code_unit| build_php_clone_candidate_data(self, &code_unit, weights))
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
}

#[cfg(any(test, feature = "test-support"))]
impl crate::analyzer::AnalyzerTestHooks for PhpAnalyzer {
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
}

static PHP_USAGE_STRATEGY: PhpUsageGraphStrategy = PhpUsageGraphStrategy::new();

pub(crate) struct PhpSupport;

impl LanguageSupport for PhpSupport {
    fn language(&self) -> Language {
        Language::Php
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
        resolve_analyzer::<PhpAnalyzer>(analyzer).map(|value| value as _)
    }

    fn ecosystem(&self) -> UsageEcosystem {
        UsageEcosystem::Php
    }

    fn usage_strategy(&self) -> &'static dyn GraphUsageAnalyzer {
        &PHP_USAGE_STRATEGY
    }

    fn edge_pass(&self) -> Option<&'static dyn LanguageEdgePass> {
        Some(&PhpEdgePass)
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
        build_php_usage_edges(ctx.analyzer, ctx.fqns, ctx.keep_file).map(LanguageEdgeSites)
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
        DeadCodeBulkPreflight::Ready {
            label: "PHP",
            files: analyzable_file_count(analyzer, Language::Php),
        }
    }

    fn build(
        &self,
        analyzer: &dyn IAnalyzer,
        candidates: &[CodeUnit],
    ) -> Option<DeadCodeBulkEdges> {
        let nodes = fqn_bulk_nodes(
            analyzer,
            Language::Php,
            |unit| unit.is_function() || unit.is_class(),
            candidates,
        );
        build_php_usage_edges(analyzer, &nodes, |_| true)
            .map(|edges| DeadCodeBulkEdges::Fqn(Arc::new(edges)))
    }
}
