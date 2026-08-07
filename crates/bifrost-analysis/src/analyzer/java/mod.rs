mod adapter;
mod cache;
mod clones;
pub(crate) mod diagnostics;
mod hierarchy;
pub(crate) mod imports;
mod semantic;
mod structural;
use crate::analyzer::Range;
use crate::analyzer::store::LimitedQueryRows;

use crate::analyzer::clone_detection::{
    CloneCandidateProfile, detect_structural_clone_smells, refine_clone_similarity_with_ast,
};
use crate::analyzer::common::{is_unparseable_source, language_for_file as file_language};
use crate::analyzer::languages::{
    DeadCodeBulkEdges, DeadCodeBulkPreflight, DeadCodeBulkProof, DeadCodeRouting, DeadCodeSupport,
    EdgePassId, EdgeSiteScanCtx, EdgeWeightScanCtx, LanguageEdgePass, LanguageEdgeSites,
    LanguageEdgeWeights, LanguageSupport, TypeLookupQuery, TypeLookupResolver,
    analyzable_file_count, fqn_bulk_nodes, overloaded_function_fqns,
};
use crate::analyzer::tree_sitter_analyzer::FileState;
use crate::analyzer::usages::GraphUsageAnalyzer;
use crate::analyzer::usages::get_type::{TypeLookupOutcome, resolve_java_type};
use crate::analyzer::usages::java_graph::{
    JavaDeadCodeBulkEligibility, JavaUsageGraphStrategy, build_java_usage_edge_weights,
    build_java_usage_edges, dead_code_bulk_eligibility,
};
use crate::analyzer::usages::workspace_graph::UsageEcosystem;
use crate::analyzer::{
    AnalyzerConfig, AnalyzerStoreContext, BuildProgress, BuildProgressEvent, BulkFileStateSource,
    CloneSmell, CloneSmellWeights, CodeUnit, DeclarationKind, ExceptionHandlingAnalysis,
    ExceptionSmellWeights, ForwardQueryProvider, IAnalyzer, ImportAnalysisProvider, ImportInfo,
    Language, Project, ProjectFile, SignatureMetadata, TestAssertionSmell, TestAssertionWeights,
    TestDetectionProvider, TreeSitterAnalyzer, TypeHierarchyProvider, UsageFactsIndex,
    resolve_analyzer,
};
use crate::hash::{HashMap, HashSet};
use std::collections::BTreeSet;
use std::sync::Arc;

use crate::analyzer::java::imports::JavaTypeResolution;
use crate::analyzer::jvm::dependency_discovery::is_jvm_dependency_input;
use crate::analyzer::jvm::external::JvmExternalDeclarationIndex;
use crate::analyzer::structural::resolution::{BoundaryStatus, PrecedenceTier};
pub(crate) use adapter::JavaAdapter;
use brokk_bifrost_core::analyzer::prepared_syntax::PreparedSyntaxTree;
use brokk_bifrost_jvm::java::declarations::{
    find_nearest_declaration_from_node, is_comment_node, is_declaration_parent,
    is_java_anonymous_structure, node_text, normalize_java_full_name, parse_tree,
};
use brokk_bifrost_jvm::java::exceptions::detect_exception_handling_smells_java;
use brokk_bifrost_jvm::java::graph_support::{
    JavaSource, java_constructor_context, java_extract_type_identifiers, java_package_name_of,
    resolve_java_forward_type_name, resolve_java_forward_type_name_candidates,
};
use brokk_bifrost_jvm::java::test_detection::detect_test_assertion_smells_java;
use cache::JavaMemoCaches;
use clones::build_clone_candidate_data;

#[derive(Clone)]
pub struct JavaAnalyzer {
    inner: TreeSitterAnalyzer<JavaAdapter>,
    memo_caches: Arc<JavaMemoCaches>,
    java_config: crate::analyzer::JvmAnalyzerConfig,
    pub(crate) external_index: Arc<std::sync::OnceLock<JvmExternalDeclarationIndex>>,
}

crate::analyzer::impl_forward_query_provider!(JavaAnalyzer);

impl JavaAnalyzer {
    pub(crate) fn clone_with_project(&self, project: Arc<dyn Project>) -> Self {
        let mut clone = self.clone();
        clone.inner = clone.inner.clone_with_project(project);
        clone.external_index = Arc::new(std::sync::OnceLock::new());
        clone
    }

    pub fn new(project: Arc<dyn Project>) -> Self {
        Self::new_with_config(project, AnalyzerConfig::default())
    }

    pub fn new_with_config(project: Arc<dyn Project>, config: AnalyzerConfig) -> Self {
        let memo_budget = config.memo_cache_budget_bytes();
        let java_config = config.jvm.clone();
        let inner = TreeSitterAnalyzer::new_with_config(project, JavaAdapter, config);
        Self {
            inner,
            memo_caches: Arc::new(JavaMemoCaches::new(memo_budget)),
            java_config,
            external_index: Arc::new(std::sync::OnceLock::new()),
        }
    }

    pub fn new_with_progress<F>(project: Arc<dyn Project>, progress: F) -> Self
    where
        F: Fn(BuildProgressEvent) + Send + Sync + 'static,
    {
        Self::new_with_config_and_progress(project, AnalyzerConfig::default(), progress)
    }

    pub fn new_with_config_and_progress<F>(
        project: Arc<dyn Project>,
        config: AnalyzerConfig,
        progress: F,
    ) -> Self
    where
        F: Fn(BuildProgressEvent) + Send + Sync + 'static,
    {
        let memo_budget = config.memo_cache_budget_bytes();
        let java_config = config.jvm.clone();
        let inner = TreeSitterAnalyzer::new_with_config_and_progress(
            project,
            JavaAdapter,
            config,
            progress,
        );
        Self {
            inner,
            memo_caches: Arc::new(JavaMemoCaches::new(memo_budget)),
            java_config,
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
        let java_config = config.jvm.clone();
        let inner = TreeSitterAnalyzer::new_with_config_storage_context_and_progress(
            project,
            JavaAdapter,
            config,
            store_context,
            progress,
        )?;
        Ok(Self {
            inner,
            memo_caches: Arc::new(JavaMemoCaches::new(memo_budget)),
            java_config,
            external_index: Arc::new(std::sync::OnceLock::new()),
        })
    }

    pub fn from_project<P>(project: P) -> Self
    where
        P: Project + 'static,
    {
        Self::new(Arc::new(project))
    }

    pub fn from_project_with_config<P>(project: P, config: AnalyzerConfig) -> Self
    where
        P: Project + 'static,
    {
        Self::new_with_config(Arc::new(project), config)
    }

    pub fn from_project_with_progress<P, F>(project: P, progress: F) -> Self
    where
        P: Project + 'static,
        F: Fn(BuildProgressEvent) + Send + Sync + 'static,
    {
        Self::new_with_progress(Arc::new(project), progress)
    }

    pub fn from_project_with_config_and_progress<P, F>(
        project: P,
        config: AnalyzerConfig,
        progress: F,
    ) -> Self
    where
        P: Project + 'static,
        F: Fn(BuildProgressEvent) + Send + Sync + 'static,
    {
        Self::new_with_config_and_progress(Arc::new(project), config, progress)
    }

    pub fn inner(&self) -> &TreeSitterAnalyzer<JavaAdapter> {
        &self.inner
    }

    pub fn normalize_full_name(&self, fq_name: &str) -> String {
        normalize_java_full_name(fq_name)
    }

    pub fn is_anonymous_structure(&self, fq_name: &str) -> bool {
        is_java_anonymous_structure(fq_name)
    }

    pub fn extract_type_identifiers(&self, source: &str) -> BTreeSet<String> {
        java_extract_type_identifiers(source)
    }

    pub fn resolve_type_name_in_file(
        &self,
        file: &ProjectFile,
        raw_name: &str,
    ) -> Option<CodeUnit> {
        resolve_java_forward_type_name(self, file, raw_name)
    }

    /// Every candidate the deciding type-name tier produced for `raw_name`.
    /// More than one entry means colliding on-demand imports supplied the same
    /// simple name, so no candidate is provably unique (issue #1602).
    pub fn resolve_type_name_candidates_in_file(
        &self,
        file: &ProjectFile,
        raw_name: &str,
    ) -> Vec<CodeUnit> {
        resolve_java_forward_type_name_candidates(self, file, raw_name)
    }

    pub fn is_known_type_name_in_file(&self, file: &ProjectFile, raw_name: &str) -> bool {
        self.resolve_type_name_with_external(file, raw_name)
            .is_some()
    }

    pub fn package_name_of(&self, file: &ProjectFile) -> Option<String> {
        java_package_name_of(self, file)
    }

    /// How far a lookup for `name` from `file` could see past the workspace,
    /// and the external type it landed on when it landed on one.
    ///
    /// This reads the external declaration index that the resolver itself
    /// consults; it performs no new resolution and cannot change one. The three
    /// answers it distinguishes are the ones a single "unresolvable import"
    /// bucket cannot: the name is externally indexed, the build declared
    /// artifacts the index could not finish reading (so the name may be there),
    /// or nothing is known.
    pub(crate) fn external_boundary_evidence(
        &self,
        file: &ProjectFile,
        name: &str,
    ) -> (BoundaryStatus, Option<String>) {
        let external = self.external_declaration_index();
        if let Some(JavaTypeResolution::External(external_type)) =
            self.resolve_type_name_with_external(file, name)
        {
            return (
                BoundaryStatus::ExternalIndexed,
                Some(external_type.fqn().to_owned()),
            );
        }
        if external.production_diagnostic_count() > 0 {
            return (BoundaryStatus::ExternalDeclaredUnindexed, None);
        }
        (BoundaryStatus::ExternalUnknown, None)
    }

    pub(crate) fn external_declaration_index(&self) -> &JvmExternalDeclarationIndex {
        self.external_index.get_or_init(|| {
            JvmExternalDeclarationIndex::build_for_project(&self.java_config, self.inner.project())
        })
    }

    pub(crate) fn bulk_file_states(
        &self,
        files: impl IntoIterator<Item = ProjectFile>,
        source_mode: BulkFileStateSource,
    ) -> HashMap<ProjectFile, FileState> {
        self.inner.bulk_file_states(files, source_mode)
    }

    /// Classify exact-FQN callable candidates and the source-level constructor
    /// shape from one coherent parser snapshot.
    pub(crate) fn constructor_context(
        &self,
        owner: &CodeUnit,
        candidates: Vec<CodeUnit>,
        call_arity: usize,
    ) -> (Vec<CodeUnit>, bool) {
        java_constructor_context(self, owner, candidates, call_arity)
    }
}

/// The analyzer-resident products the crate-side Java logic resolves through.
///
/// Every method forwards to one of this analyzer's own accessors or memo
/// cells, so the cells stay here and the free functions in
/// [`brokk_bifrost_jvm::java::graph_support`] cannot reach past this surface.
impl JavaSource for JavaAnalyzer {
    fn all_files(&self) -> Vec<ProjectFile> {
        self.inner.all_files()
    }

    fn cached_package_name(&self, file: &ProjectFile) -> Option<Arc<str>> {
        if let Some(package) = self.memo_caches.package_names.get(file) {
            return Some(package);
        }
        let package: Arc<str> = Arc::from(self.inner.package_name_of(file)?);
        self.memo_caches
            .package_names
            .insert(file.clone(), Arc::clone(&package));
        Some(package)
    }

    fn resolved_imports(&self, file: &ProjectFile) -> Arc<HashMap<String, CodeUnit>> {
        self.resolve_imports(file)
    }

    fn forward_definition_fqn(&self, fqn: &str) -> Vec<CodeUnit> {
        ForwardQueryProvider::forward_definition_fqn(self, fqn)
    }

    fn usage_definitions(&self) -> &dyn crate::analyzer::BoundedDefinitionLookup {
        self.inner.global_usage_definition_index_ref()
    }

    fn source_types_in_package(&self, package_name: &str) -> Vec<CodeUnit> {
        let mut types: Vec<_> = self
            .inner
            .global_usage_definition_index()
            .package_types()
            .filter(|((package, _), _)| package == package_name)
            .flat_map(|(_, units)| units.iter().cloned())
            .collect();
        types.sort();
        types.dedup();
        types
    }

    fn type_identifiers_of(&self, file: &ProjectFile) -> Option<HashSet<String>> {
        self.inner.type_identifiers_of(file)
    }

    fn raw_supertypes_of(&self, code_unit: &CodeUnit) -> Vec<String> {
        self.inner.raw_supertypes_of(code_unit)
    }

    fn prepared_syntax(&self, file: &ProjectFile) -> Option<Arc<PreparedSyntaxTree>> {
        self.inner.prepared_syntax(file)
    }

    fn external_boundary_evidence(
        &self,
        file: &ProjectFile,
        name: &str,
    ) -> (BoundaryStatus, Option<String>) {
        JavaAnalyzer::external_boundary_evidence(self, file, name)
    }

    fn trace_type_name_tier(&self, normalized: &str, units: &[CodeUnit], tier: PrecedenceTier) {
        imports::trace_tier(normalized, units, tier);
    }

    fn trace_explicit_import_win(
        &self,
        file: &ProjectFile,
        normalized: &str,
        unit: Option<&CodeUnit>,
        imports: &[ImportInfo],
    ) {
        imports::trace_explicit_import_win(file, normalized, unit, imports);
    }
}

use crate::analyzer::CodeUnitIndex;

impl CodeUnitIndex for JavaAnalyzer {
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

    fn all_declarations(&self) -> Box<dyn Iterator<Item = CodeUnit> + '_> {
        self.inner.all_declarations()
    }

    fn all_declarations_with_primary_ranges(
        &self,
    ) -> Vec<(CodeUnit, Option<crate::analyzer::Range>)> {
        self.inner.all_declarations_with_primary_ranges()
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

    fn direct_children_in_file(&self, code_unit: &CodeUnit) -> Vec<CodeUnit> {
        self.inner.direct_children_in_file(code_unit)
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

impl IAnalyzer for JavaAnalyzer {
    #[cfg(any(test, feature = "test-support"))]
    fn test_hooks(&self) -> &dyn crate::analyzer::AnalyzerTestHooks {
        self
    }

    fn semantic_diagnostics(
        &self,
        file: &ProjectFile,
        source: &str,
    ) -> crate::analyzer::SemanticDiagnosticReport {
        diagnostics::collect_java_semantic_diagnostics(self, file, source)
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

    fn usage_facts_index(&self) -> &UsageFactsIndex {
        self.inner.usage_facts_index()
    }

    fn declaration_syntax_kind(&self, code_unit: &CodeUnit) -> Option<&'static str> {
        self.inner.declaration_syntax_kind(code_unit)
    }

    fn import_statements(&self, file: &ProjectFile) -> Vec<String> {
        self.inner.import_statements(file)
    }

    fn compute_cognitive_complexities(&self, file: &ProjectFile) -> Vec<(CodeUnit, u32)> {
        self.inner.compute_cognitive_complexities(file)
    }

    fn update(&self, changed_files: &BTreeSet<ProjectFile>) -> Self {
        let external_index = if changed_files.iter().any(is_jvm_dependency_input) {
            Arc::new(std::sync::OnceLock::new())
        } else {
            self.external_index.clone()
        };
        Self {
            inner: self.inner.update(changed_files),
            memo_caches: Arc::new(JavaMemoCaches::new(self.memo_caches.budget_bytes())),
            java_config: self.java_config.clone(),
            external_index,
        }
    }

    fn update_all(&self) -> Self {
        Self {
            inner: self.inner.update_all(),
            memo_caches: Arc::new(JavaMemoCaches::new(self.memo_caches.budget_bytes())),
            java_config: self.java_config.clone(),
            external_index: Arc::new(std::sync::OnceLock::new()),
        }
    }

    fn import_analysis_provider(&self) -> Option<&dyn ImportAnalysisProvider> {
        Some(self)
    }

    fn type_hierarchy_provider(&self) -> Option<&dyn TypeHierarchyProvider> {
        Some(self)
    }

    fn member_family_provider(&self) -> Option<&dyn crate::analyzer::usages::MemberFamilyProvider> {
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

    fn parse_errors(&self, file: &ProjectFile) -> Option<Vec<crate::analyzer::ParseError>> {
        self.inner.parse_errors(file)
    }

    fn extract_call_receiver(&self, reference: &str) -> Option<String> {
        self.inner.extract_call_receiver(reference)
    }

    fn is_access_expression(&self, file: &ProjectFile, start_byte: usize, end_byte: usize) -> bool {
        let Ok(source) = self.inner.project().read_source(file) else {
            return true;
        };
        let Some(tree) = parse_tree(&source) else {
            return true;
        };
        let root = tree.root_node();
        let Some(node) = root.named_descendant_for_byte_range(start_byte, end_byte) else {
            return true;
        };

        let mut walk = Some(node);
        while let Some(current) = walk {
            if is_comment_node(current) {
                return false;
            }
            walk = current.parent();
        }

        let mut current = Some(node);
        while let Some(candidate) = current {
            if let Some(parent) = candidate.parent()
                && is_declaration_parent(parent.kind())
                && let Some(name_node) = parent.child_by_field_name("name")
                && name_node.start_byte() == start_byte
            {
                return false;
            }
            current = candidate.parent();
        }

        if let Some(parent) = node.parent() {
            if parent.kind() == "field_access"
                && let Some(field_node) = parent.child_by_field_name("field")
                && field_node.start_byte() == node.start_byte()
            {
                return true;
            }
            if parent.kind() == "method_invocation"
                && let Some(name_node) = parent.child_by_field_name("name")
                && name_node.start_byte() == node.start_byte()
            {
                return true;
            }
        }

        let identifier = node_text(node, &source).trim().to_string();
        if identifier.is_empty() {
            return true;
        }

        match find_nearest_declaration_from_node(node, &identifier, &source) {
            Some(info) => !matches!(
                info.kind,
                DeclarationKind::Parameter
                    | DeclarationKind::LocalVariable
                    | DeclarationKind::CatchParameter
                    | DeclarationKind::EnhancedForVariable
                    | DeclarationKind::ResourceVariable
                    | DeclarationKind::PatternVariable
                    | DeclarationKind::LambdaParameter
            ),
            None => true,
        }
    }

    fn find_nearest_declaration(
        &self,
        file: &ProjectFile,
        start_byte: usize,
        end_byte: usize,
        ident: &str,
    ) -> Option<crate::analyzer::DeclarationInfo> {
        let Ok(source) = self.inner.project().read_source(file) else {
            return None;
        };
        let tree = parse_tree(&source)?;
        let root = tree.root_node();
        let node = root.named_descendant_for_byte_range(start_byte, end_byte)?;
        find_nearest_declaration_from_node(node, ident, &source)
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

    fn in_test_region(&self, code_unit: &crate::analyzer::CodeUnit) -> bool {
        self.inner.in_test_region(code_unit)
    }

    fn find_exception_handling_smells(
        &self,
        file: &ProjectFile,
        weights: ExceptionSmellWeights,
    ) -> ExceptionHandlingAnalysis {
        if file_language(file) != Language::Java {
            return ExceptionHandlingAnalysis::Unsupported {
                reason: format!(
                    "Java exception semantics do not apply to {}",
                    file.rel_path().display()
                ),
            };
        }
        let source = match self.inner.project().read_source(file) {
            Ok(source) => source,
            Err(error) => {
                return ExceptionHandlingAnalysis::Failed {
                    message: format!("failed to read {}: {error}", file.rel_path().display()),
                };
            }
        };
        if is_unparseable_source(&source) {
            return ExceptionHandlingAnalysis::Failed {
                message: format!("failed to parse {}", file.rel_path().display()),
            };
        }
        match detect_exception_handling_smells_java(self, file, &source, &weights) {
            Some(findings) => ExceptionHandlingAnalysis::Analyzed(findings),
            None => ExceptionHandlingAnalysis::Failed {
                message: format!("failed to parse {}", file.rel_path().display()),
            },
        }
    }

    fn find_test_assertion_smells(
        &self,
        file: &ProjectFile,
        weights: TestAssertionWeights,
    ) -> Vec<TestAssertionSmell> {
        if file_language(file) != Language::Java || !self.contains_tests(file) {
            return Vec::new();
        }
        let Ok(source) = self.inner.project().read_source(file) else {
            return Vec::new();
        };
        detect_test_assertion_smells_java(self, file, &source, &weights)
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
            .filter(|file| file_language(file) == Language::Java)
            .cloned()
            .collect();
        if requested_files.is_empty() {
            return Vec::new();
        }

        let all_candidates: Vec<CloneCandidateProfile> = self
            .get_all_declarations()
            .into_iter()
            .filter(|code_unit| {
                code_unit.is_function() && file_language(code_unit.source()) == Language::Java
            })
            .filter_map(|code_unit| build_clone_candidate_data(self, &code_unit, weights))
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
}

#[cfg(any(test, feature = "test-support"))]
impl crate::analyzer::AnalyzerTestHooks for JavaAnalyzer {
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
}

static JAVA_USAGE_STRATEGY: JavaUsageGraphStrategy = JavaUsageGraphStrategy::new();

pub(crate) struct JavaSupport;

impl LanguageSupport for JavaSupport {
    fn language(&self) -> Language {
        Language::Java
    }

    fn declaration_ranges_limited(
        &self,
        analyzer: &dyn IAnalyzer,
        unit: &CodeUnit,
        limit: usize,
    ) -> Option<LimitedQueryRows<Range>> {
        resolve_analyzer::<JavaAnalyzer>(analyzer)
            .map(|java| java.inner().ranges_limited(unit, limit))
    }

    fn forward_query_provider<'a>(
        &self,
        analyzer: &'a dyn IAnalyzer,
    ) -> Option<&'a dyn ForwardQueryProvider> {
        resolve_analyzer::<JavaAnalyzer>(analyzer).map(|value| value as _)
    }

    fn ecosystem(&self) -> UsageEcosystem {
        UsageEcosystem::Jvm
    }

    fn usage_strategy(&self) -> &'static dyn GraphUsageAnalyzer {
        &JAVA_USAGE_STRATEGY
    }

    fn edge_pass(&self) -> Option<&'static dyn LanguageEdgePass> {
        Some(&JavaEdgePass)
    }

    fn dead_code(&self) -> DeadCodeSupport {
        DeadCodeSupport {
            strategy: Some(&JAVA_USAGE_STRATEGY),
            bulk: Some(&JavaDeadCodeBulk),
        }
    }

    fn type_lookup(&self) -> Option<&'static dyn TypeLookupResolver> {
        Some(&JavaSupport)
    }

    fn parser_language(&self, _flavor: crate::analyzer::ParserFlavor) -> tree_sitter::Language {
        tree_sitter_java::LANGUAGE.into()
    }

    fn structural_spec(&self) -> &'static dyn crate::analyzer::structural::StructuralSpec {
        &brokk_bifrost_jvm::java::structural::JAVA_STRUCTURAL_SPEC
    }

    fn highlight_query(&self) -> Option<&'static str> {
        Some(tree_sitter_java::HIGHLIGHTS_QUERY)
    }
}

/// One of three distinct JVM passes. Java, Scala and Kotlin resolve over the same
/// candidate space but scan only files of their own language, so the three passes cover
/// disjoint call sites and merge without double counting.
struct JavaEdgePass;

impl LanguageEdgePass for JavaEdgePass {
    fn id(&self) -> EdgePassId {
        EdgePassId::Java
    }

    fn edge_sites(&self, ctx: &EdgeSiteScanCtx<'_>) -> Option<LanguageEdgeSites> {
        build_java_usage_edges(ctx.analyzer, ctx.fqns, ctx.keep_file).map(LanguageEdgeSites)
    }

    fn edge_weights(&self, ctx: &EdgeWeightScanCtx<'_>) -> Option<LanguageEdgeWeights> {
        build_java_usage_edge_weights(ctx.analyzer, ctx.fqns, ctx.keep_file)
            .map(LanguageEdgeWeights::Fqn)
    }
}

impl TypeLookupResolver for JavaSupport {
    fn resolve_type(&self, query: TypeLookupQuery<'_>) -> TypeLookupOutcome {
        query.support.set_language(query.language);
        resolve_java_type(
            query.analyzer,
            query.support,
            query.file,
            query.source,
            query.tree,
            query.site,
        )
    }
}

/// Java's bulk routing needs three whole-workspace facts, each computed at most once per
/// report: which function names are overloaded (ambiguous to an fqn-keyed proof), whether
/// any file uses a static import, and whether the workspace also holds Scala sources that
/// could call into Java.
#[derive(Default)]
struct JavaDeadCodeMemo {
    file_count: Option<usize>,
    overloaded_fqns: Option<HashSet<String>>,
    static_imports_present: Option<bool>,
    scala_files_present: Option<bool>,
}

struct JavaDeadCodeBulk;

impl DeadCodeBulkProof for JavaDeadCodeBulk {
    fn id(&self) -> EdgePassId {
        EdgePassId::Java
    }

    fn new_memo(&self) -> Box<dyn std::any::Any + Send> {
        Box::new(JavaDeadCodeMemo::default())
    }

    fn needs_precise_scan(&self, routing: DeadCodeRouting<'_>) -> bool {
        let DeadCodeRouting {
            analyzer,
            candidate,
            file_cap,
            memo,
        } = routing;
        let JavaDeadCodeMemo {
            file_count,
            overloaded_fqns,
            static_imports_present,
            scala_files_present,
        } = memo.downcast_mut().expect("Java bulk memo");
        if *file_count.get_or_insert_with(|| analyzable_file_count(analyzer, Language::Java))
            > file_cap
        {
            return true;
        }

        let empty_overloads = HashSet::default();
        let overloads = if candidate.is_function() {
            overloaded_fqns
                .get_or_insert_with(|| overloaded_function_fqns(analyzer, Language::Java))
        } else {
            &empty_overloads
        };
        let has_static_imports = candidate.is_function()
            && *static_imports_present.get_or_insert_with(|| java_static_imports_present(analyzer));
        let has_scala_files = *scala_files_present
            .get_or_insert_with(|| analyzable_file_count(analyzer, Language::Scala) > 0);

        matches!(
            dead_code_bulk_eligibility(
                analyzer,
                candidate,
                overloads,
                has_static_imports,
                has_scala_files,
            ),
            JavaDeadCodeBulkEligibility::NeedsPrecise
        )
    }

    fn preflight(&self, analyzer: &dyn IAnalyzer) -> DeadCodeBulkPreflight {
        DeadCodeBulkPreflight::Ready {
            label: "Java",
            files: analyzable_file_count(analyzer, Language::Java),
        }
    }

    fn build(
        &self,
        analyzer: &dyn IAnalyzer,
        candidates: &[CodeUnit],
    ) -> Option<DeadCodeBulkEdges> {
        let nodes = fqn_bulk_nodes(
            analyzer,
            Language::Java,
            |unit| unit.is_function() || unit.is_class(),
            candidates,
        );
        build_java_usage_edges(analyzer, &nodes, |_| true)
            .map(|edges| DeadCodeBulkEdges::Fqn(Arc::new(edges)))
    }
}

fn java_static_imports_present(analyzer: &dyn IAnalyzer) -> bool {
    analyzer
        .project()
        .analyzable_files(Language::Java)
        .is_ok_and(|files| {
            files.into_iter().any(|file| {
                file.read_to_string()
                    .is_ok_and(|source| source.contains("import static "))
            })
        })
}

/// Java is the first language family of the #1477 M4 rollout.
///
/// Both directions delegate to the shared Java relation with `self` as both
/// the declaration source and the hierarchy source. The multi-analyzer
/// overrides the hierarchy argument with its own realm-aware walk, which is why
/// the relation takes the two separately.
impl crate::analyzer::usages::MemberFamilyProvider for JavaAnalyzer {
    fn member_family_capability(
        &self,
        member: &CodeUnit,
    ) -> crate::analyzer::structural::resolution::MemberFamilyCapability {
        crate::analyzer::usages::java_member_family_capability(self, member)
    }

    fn forward_member_family(
        &self,
        member: &CodeUnit,
    ) -> crate::analyzer::usages::MemberFamilyAnswer {
        crate::analyzer::usages::java_forward_member_family(self, self, member)
    }

    fn inverse_member_family(
        &self,
        member: &CodeUnit,
    ) -> crate::analyzer::usages::MemberFamilyAnswer {
        crate::analyzer::usages::java_inverse_member_family(self, self, member)
    }
}
