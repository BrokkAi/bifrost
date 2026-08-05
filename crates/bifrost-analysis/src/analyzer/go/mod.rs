mod adapter;
mod artifact;
mod cache;
mod clones;
mod dependency_discovery;
pub(crate) mod diagnostics;
mod imports;
mod semantic;
use crate::analyzer::Range;

use crate::analyzer::clone_detection::detect_language_structural_clone_smells;
use crate::analyzer::common::language_for_file as file_language;
use crate::analyzer::languages::{
    BoundedReceiverQuery, DeadCodeBulkEdges, DeadCodeBulkPreflight, DeadCodeBulkProof,
    DeadCodeRouting, DeadCodeSupport, EdgePassId, EdgeSiteScanCtx, EdgeWeightScanCtx,
    LanguageEdgePass, LanguageEdgeSites, LanguageEdgeWeights, LanguageSupport,
    StructuralReceiverResolver, TypeLookupQuery, TypeLookupResolver, analyzable_file_count,
    fqn_bulk_nodes,
};
use crate::analyzer::store::LimitedQueryRows;
use crate::analyzer::usages::GraphUsageAnalyzer;
use crate::analyzer::usages::get_definition::{
    BoundedResolution, DefinitionLookupOutcome, resolve_go_bounded,
};
use crate::analyzer::usages::get_type::{
    TypeLookupOutcome, resolve_go_type, resolve_go_type_bounded,
};
use crate::analyzer::usages::go_graph::{
    GoUsageGraphStrategy, build_go_usage_edge_weights, build_go_usage_edges,
    go_implicit_entry_point,
};
use crate::analyzer::usages::workspace_graph::UsageEcosystem;
use crate::analyzer::{
    AnalyzerConfig, AnalyzerStoreContext, BuildProgress, CloneSmell, CloneSmellWeights, CodeUnit,
    ForwardQueryProvider, IAnalyzer, ImportAnalysisProvider, Language, Project, ProjectFile,
    SignatureMetadata, TestAssertionSmell, TestAssertionWeights, TestDetectionProvider,
    TreeSitterAnalyzer, TypeAliasProvider, TypeHierarchyProvider, resolve_analyzer,
};
use std::collections::BTreeSet;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::Ordering;

pub(crate) use adapter::GoAdapter;
pub use artifact::GoDependencyPackAdapter;
// The Go declaration walk lives in the go crate; the rest of analysis (artifact,
// semantic) still reaches its helpers through `super::declarations::`.
pub(crate) use brokk_bifrost_go::declarations;
pub(crate) use brokk_bifrost_go::declarations::{
    determine_go_package_name, go_structured_type_identity_bounded,
};
use brokk_bifrost_go::hierarchy::GoHierarchyIndex;
pub(crate) use brokk_bifrost_go::packages;
pub(crate) use brokk_bifrost_go::packages::GO_MODULE_SCOPE_SEGMENT;
use brokk_bifrost_go::packages::canonical_go_package_name;
use brokk_bifrost_go::test_detection::detect_go_test_assertion_smells;
use cache::GoMemoCaches;
use clones::build_go_clone_candidate_data;
pub use dependency_discovery::resolve_go_semantic_pack_dependencies;

#[derive(Clone)]
pub struct GoAnalyzer {
    inner: TreeSitterAnalyzer<GoAdapter>,
    memo_caches: GoMemoCaches,
}

crate::analyzer::impl_forward_query_provider!(GoAnalyzer);

impl GoAnalyzer {
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
        Self {
            inner: TreeSitterAnalyzer::new_with_config(project, GoAdapter, config),
            memo_caches: GoMemoCaches::new(memo_budget),
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
            GoAdapter,
            config,
            store_context,
            progress,
        )?;
        Ok(Self {
            inner,
            memo_caches: GoMemoCaches::new(memo_budget),
        })
    }

    pub fn from_project<P>(project: P) -> Self
    where
        P: Project + 'static,
    {
        Self::new(Arc::new(project))
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
        let mut candidates =
            self.inner
                .lookup_declarations_by_identifier_limited(name, limit, continue_query);
        if candidates.complete {
            candidates
                .rows
                .retain(|candidate| candidate.fq_name() == exact_fqn);
        }
        candidates
    }

    pub(crate) fn import_info_limited(
        &self,
        file: &ProjectFile,
        limit: usize,
    ) -> LimitedQueryRows<crate::analyzer::ImportInfo> {
        self.inner.import_info_of_limited(file, limit)
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
    ) -> LimitedQueryRows<crate::analyzer::Range> {
        self.inner.ranges_limited(code_unit, limit)
    }

    pub(crate) fn raw_supertypes(&self, code_unit: &CodeUnit) -> Vec<String> {
        self.inner.raw_supertypes_of(code_unit)
    }

    pub(crate) fn raw_supertypes_limited(
        &self,
        code_unit: &CodeUnit,
        limit: usize,
    ) -> LimitedQueryRows<String> {
        self.inner.raw_supertypes_limited(code_unit, limit)
    }

    pub fn determine_package_name(&self, source: &str) -> String {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_go::LANGUAGE.into())
            .expect("failed to load go parser");
        let Some(tree) = parser.parse(source, None) else {
            return String::new();
        };
        determine_go_package_name(tree.root_node(), source)
    }

    pub(crate) fn canonical_package_name_from_tree(
        &self,
        file: &ProjectFile,
        source: &str,
        root: tree_sitter::Node<'_>,
    ) -> String {
        let declared = determine_go_package_name(root, source);
        canonical_go_package_name(file, &declared)
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

    pub(crate) fn package_clause_of(&self, file: &ProjectFile) -> Option<String> {
        self.inner.content_qualifier_of(file)
    }

    pub(crate) fn workspace_path_index(&self) -> &packages::GoWorkspacePathIndex {
        self.memo_caches.workspace_path_index.get_or_init(|| {
            self.memo_caches
                .workspace_path_index_build_count
                .fetch_add(1, Ordering::Relaxed);
            packages::GoWorkspacePathIndex::build(self.project())
        })
    }

    #[doc(hidden)]
    pub fn workspace_path_index_build_count_for_test(&self) -> usize {
        self.memo_caches.workspace_path_index_build_count()
    }

    pub(crate) fn package_clause_names(&self) -> &crate::hash::HashMap<ProjectFile, String> {
        self.memo_caches.package_clause_names.get_or_init(|| {
            self.get_analyzed_files()
                .into_iter()
                .filter(|file| file_language(file) == Language::Go)
                .filter_map(|file| {
                    let source = self.project().read_source(&file).ok()?;
                    let package_name = self.determine_package_name(&source);
                    (!package_name.is_empty()).then_some((file, package_name))
                })
                .collect()
        })
    }

    pub fn format_test_module(path: impl AsRef<Path>) -> String {
        let path = path.as_ref();
        let normalized = path
            .to_string_lossy()
            .replace('\\', "/")
            .trim()
            .trim_start_matches('/')
            .trim_end_matches('/')
            .trim_matches('.')
            .trim_matches('/')
            .to_string();
        if normalized.is_empty() {
            ".".to_string()
        } else {
            format!("./{normalized}")
        }
    }

    pub fn get_test_modules_static(files: &[ProjectFile]) -> Vec<String> {
        let mut modules: Vec<_> = files
            .iter()
            .map(|file| {
                Self::format_test_module(file.rel_path().parent().unwrap_or_else(|| Path::new(".")))
            })
            .collect();
        modules.sort();
        modules.dedup();
        modules
    }
}

impl TypeAliasProvider for GoAnalyzer {
    fn is_type_alias(&self, code_unit: &CodeUnit) -> bool {
        self.inner.is_type_alias(code_unit)
    }
}

impl TypeHierarchyProvider for GoAnalyzer {
    fn get_direct_ancestors(&self, code_unit: &CodeUnit) -> Vec<CodeUnit> {
        self.memo_caches
            .hierarchy_index
            .get_or_init(|| GoHierarchyIndex::build(&self.inner, self))
            .direct_ancestors(code_unit)
    }

    fn get_direct_descendants(&self, code_unit: &CodeUnit) -> crate::hash::HashSet<CodeUnit> {
        self.memo_caches
            .hierarchy_index
            .get_or_init(|| GoHierarchyIndex::build(&self.inner, self))
            .direct_descendants(code_unit)
    }

    fn supports_type_hierarchy(&self, code_unit: &CodeUnit) -> bool {
        self.memo_caches
            .hierarchy_index
            .get_or_init(|| GoHierarchyIndex::build(&self.inner, self))
            .supports(code_unit)
    }
}

impl TestDetectionProvider for GoAnalyzer {}

use crate::analyzer::CodeUnitIndex;

impl CodeUnitIndex for GoAnalyzer {
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
        let skeleton = self.inner.get_skeleton(code_unit)?;
        if code_unit.is_class() && !skeleton.trim_start().starts_with("type ") {
            Some(format!("type {skeleton}"))
        } else {
            Some(skeleton)
        }
    }

    fn get_skeleton_header(&self, code_unit: &CodeUnit) -> Option<String> {
        let skeleton = self.inner.get_skeleton_header(code_unit)?;
        if code_unit.is_class() && !skeleton.trim_start().starts_with("type ") {
            Some(format!("type {skeleton}"))
        } else {
            Some(skeleton)
        }
    }

    fn get_source(&self, code_unit: &CodeUnit, include_comments: bool) -> Option<String> {
        let sources = self.get_sources(code_unit, include_comments);
        (!sources.is_empty()).then(|| sources.into_iter().collect::<Vec<_>>().join("\n\n"))
    }

    fn render_source_fragment(
        &self,
        code_unit: &CodeUnit,
        mut source: String,
        declaration_start: usize,
    ) -> String {
        let Some(declaration) = source.get(declaration_start..) else {
            return source;
        };
        let declaration_has_type_keyword = declaration.trim_start().starts_with("type ")
            || source
                .get(..declaration_start)
                .is_some_and(|prefix| prefix.trim_end().ends_with("type"));
        if code_unit.is_class() && !declaration_has_type_keyword {
            source.insert_str(declaration_start, "type ");
        }
        source
    }

    fn get_sources(&self, code_unit: &CodeUnit, include_comments: bool) -> BTreeSet<String> {
        if !code_unit.is_class() {
            return self.inner.get_sources(code_unit, include_comments);
        }

        let Some(content) = self.inner.indexed_source(code_unit.source()) else {
            return BTreeSet::new();
        };
        let mut ranges = self.inner.ranges(code_unit);
        ranges.sort_by_key(|range| range.start_byte);

        ranges
            .into_iter()
            .filter_map(|range| {
                let start_byte = if include_comments {
                    crate::analyzer::tree_sitter_analyzer::expanded_comment_start(
                        &content,
                        range.start_byte,
                    )
                } else {
                    range.start_byte
                };
                let source = content.get(start_byte..range.end_byte)?.to_string();
                Some(self.render_source_fragment(
                    code_unit,
                    source,
                    range.start_byte.saturating_sub(start_byte),
                ))
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

impl IAnalyzer for GoAnalyzer {
    #[cfg(any(test, feature = "test-support"))]
    fn test_hooks(&self) -> &dyn crate::analyzer::AnalyzerTestHooks {
        self
    }

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
        Self {
            inner: self.inner.update(changed_files),
            memo_caches: GoMemoCaches::new(self.memo_caches.budget_bytes()),
        }
    }

    fn update_all(&self) -> Self {
        Self {
            inner: self.inner.update_all(),
            memo_caches: GoMemoCaches::new(self.memo_caches.budget_bytes()),
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
        let diagnostics = diagnostics::collect_go_semantic_diagnostics(self, file, source)
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

    fn import_analysis_provider(&self) -> Option<&dyn ImportAnalysisProvider> {
        Some(self)
    }

    fn type_alias_provider(&self) -> Option<&dyn TypeAliasProvider> {
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
        detect_language_structural_clone_smells(self, files, weights, Language::Go, |code_unit| {
            build_go_clone_candidate_data(self, code_unit, weights)
        })
    }

    fn find_test_assertion_smells(
        &self,
        file: &ProjectFile,
        weights: TestAssertionWeights,
    ) -> Vec<TestAssertionSmell> {
        if !self.contains_tests(file) || file_language(file) != Language::Go {
            return Vec::new();
        }
        let Ok(source) = self.inner.project().read_source(file) else {
            return Vec::new();
        };
        detect_go_test_assertion_smells(file, &source, &weights)
    }

    fn get_test_modules(&self, files: &[ProjectFile]) -> Vec<String> {
        Self::get_test_modules_static(files)
    }
}

#[cfg(any(test, feature = "test-support"))]
impl crate::analyzer::AnalyzerTestHooks for GoAnalyzer {
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

static GO_USAGE_STRATEGY: GoUsageGraphStrategy = GoUsageGraphStrategy::new();

pub(crate) struct GoSupport;

impl LanguageSupport for GoSupport {
    fn language(&self) -> Language {
        Language::Go
    }

    fn package_separator(&self) -> &'static str {
        "/"
    }

    fn signature_metadata_limited(
        &self,
        analyzer: &dyn IAnalyzer,
        unit: &CodeUnit,
        limit: usize,
    ) -> Option<LimitedQueryRows<SignatureMetadata>> {
        resolve_analyzer::<GoAnalyzer>(analyzer)
            .map(|go| go.signature_metadata_limited(unit, limit))
    }

    fn declaration_ranges_limited(
        &self,
        analyzer: &dyn IAnalyzer,
        unit: &CodeUnit,
        limit: usize,
    ) -> Option<LimitedQueryRows<Range>> {
        resolve_analyzer::<GoAnalyzer>(analyzer).map(|go| go.ranges_limited(unit, limit))
    }

    fn forward_query_provider<'a>(
        &self,
        analyzer: &'a dyn IAnalyzer,
    ) -> Option<&'a dyn ForwardQueryProvider> {
        resolve_analyzer::<GoAnalyzer>(analyzer).map(|value| value as _)
    }

    fn ecosystem(&self) -> UsageEcosystem {
        UsageEcosystem::Go
    }

    fn usage_strategy(&self) -> &'static dyn GraphUsageAnalyzer {
        &GO_USAGE_STRATEGY
    }

    fn edge_pass(&self) -> Option<&'static dyn LanguageEdgePass> {
        Some(&GoEdgePass)
    }

    fn dead_code(&self) -> DeadCodeSupport {
        DeadCodeSupport {
            strategy: Some(&GO_USAGE_STRATEGY),
            bulk: Some(&GoDeadCodeBulk),
        }
    }

    fn structural_receiver(&self) -> Option<&'static dyn StructuralReceiverResolver> {
        Some(&GoSupport)
    }

    fn type_lookup(&self) -> Option<&'static dyn TypeLookupResolver> {
        Some(&GoSupport)
    }

    fn parser_language(&self, _flavor: crate::analyzer::ParserFlavor) -> tree_sitter::Language {
        tree_sitter_go::LANGUAGE.into()
    }

    fn structural_spec(&self) -> &'static dyn crate::analyzer::structural::StructuralSpec {
        &brokk_bifrost_go::structural::GO_STRUCTURAL_SPEC
    }

    fn highlight_query(&self) -> Option<&'static str> {
        Some(tree_sitter_go::HIGHLIGHTS_QUERY)
    }
}

struct GoEdgePass;

impl LanguageEdgePass for GoEdgePass {
    fn id(&self) -> EdgePassId {
        EdgePassId::Go
    }

    fn edge_sites(&self, ctx: &EdgeSiteScanCtx<'_>) -> Option<LanguageEdgeSites> {
        build_go_usage_edges(ctx.analyzer, ctx.fqns, ctx.keep_file).map(LanguageEdgeSites)
    }

    fn edge_weights(&self, ctx: &EdgeWeightScanCtx<'_>) -> Option<LanguageEdgeWeights> {
        build_go_usage_edge_weights(ctx.analyzer, ctx.fqns, ctx.keep_file)
            .map(LanguageEdgeWeights::Fqn)
    }
}

impl StructuralReceiverResolver for GoSupport {
    fn resolve_type_bounded(
        &self,
        query: BoundedReceiverQuery<'_>,
    ) -> BoundedResolution<TypeLookupOutcome> {
        resolve_go_type_bounded(
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
        resolve_go_bounded(
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

impl TypeLookupResolver for GoSupport {
    fn resolve_type(&self, query: TypeLookupQuery<'_>) -> TypeLookupOutcome {
        resolve_go_type(
            query.analyzer,
            query.file,
            query.source,
            query.tree,
            query.site,
        )
    }
}

struct GoDeadCodeBulk;

impl DeadCodeBulkProof for GoDeadCodeBulk {
    fn id(&self) -> EdgePassId {
        EdgePassId::Go
    }

    fn needs_precise_scan(&self, routing: DeadCodeRouting<'_>) -> bool {
        routing.candidate.is_field() || go_implicit_entry_point(routing.candidate)
    }

    fn preflight(&self, analyzer: &dyn IAnalyzer) -> DeadCodeBulkPreflight {
        DeadCodeBulkPreflight::Ready {
            label: "Go",
            files: analyzable_file_count(analyzer, Language::Go),
        }
    }

    /// Module-level variables count as callers as well as declarations: a package-level
    /// `var` initializer is a real call site in Go.
    fn build(
        &self,
        analyzer: &dyn IAnalyzer,
        candidates: &[CodeUnit],
    ) -> Option<DeadCodeBulkEdges> {
        let nodes = fqn_bulk_nodes(
            analyzer,
            Language::Go,
            |unit| unit.is_function() || unit.is_class() || go_module_level_field(unit),
            candidates,
        );
        build_go_usage_edges(analyzer, &nodes, |_| true)
            .map(|edges| DeadCodeBulkEdges::Fqn(Arc::new(edges)))
    }
}

fn go_module_level_field(unit: &CodeUnit) -> bool {
    unit.is_field() && unit.short_name().starts_with("_module_.")
}

#[cfg(test)]
mod hierarchy_tests {
    //! Lives here rather than beside the builder in `brokk-bifrost-go`: the
    //! fixture needs a real `GoAnalyzer` to supply the `CodeUnitIndex` and
    //! `ImportAnalysisProvider` the hierarchy is built from.
    use super::*;
    use crate::analyzer::TestProject;
    use crate::analyzer::type_relations::TypeRelationKind;
    use std::fs;
    use tempfile::tempdir;

    fn analyzer(files: &[(&str, &str)]) -> GoAnalyzer {
        let temp = tempdir().unwrap();
        let root = temp.keep();
        fs::write(root.join("go.mod"), "module example.com/app\n\ngo 1.22\n").unwrap();
        for (path, source) in files {
            let path = root.join(path);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).unwrap();
            }
            fs::write(path, source).unwrap();
        }
        GoAnalyzer::from_project(TestProject::new(root, Language::Go))
    }

    #[test]
    fn structural_relation_records_satisfied_interface() {
        let analyzer = analyzer(&[(
            "service.go",
            "package app\ntype Runner interface { Run() error }\ntype Worker struct{}\nfunc (Worker) Run() error { return nil }\n",
        )]);
        let index = GoHierarchyIndex::build(&analyzer, &analyzer);
        assert!(index.relations().iter().any(|relation| {
            relation.kind == TypeRelationKind::StructuralSatisfaction
                && relation.from.identifier() == "Worker"
                && relation.to.identifier() == "Runner"
        }));
    }
}
