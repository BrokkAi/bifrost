mod adapter;
mod annotation;
pub use annotation::{
    JavaAnnotationTypeResolution, JavaAnnotationTypeStatus, resolve_java_annotation_type,
};
mod cache;
mod call_applicability;
mod call_conversion;
pub use call_conversion::{JavaLocalAssignmentConversionProver, JavaLocalAssignmentEvidence};
mod checked_exceptions;
pub(crate) use call_conversion::{
    JavaFormalShape, declaration_declares_array, declared_type_node, formal_shapes,
    parse_declaring_file, primitive_actual_type, primitive_converts, primitive_for_name,
};
#[cfg(any(test, feature = "test-support"))]
pub(crate) use call_conversion::{primitive_actual_type_from_syntax, primitive_type};
mod clones;
pub(crate) mod diagnostics;
mod hierarchy;
pub(crate) mod imports;
// Exercise the native consumer before the approved atomic JVM cutover.
#[cfg(any(test, feature = "test-support"))]
pub(super) mod native_call_relations;
#[cfg(any(test, feature = "test-support"))]
pub(super) mod native_points;
#[cfg(any(test, feature = "test-support"))]
pub(super) mod native_rename;
#[cfg(any(test, feature = "test-support"))]
pub(super) mod native_usages;
#[cfg(any(test, feature = "test-support"))]
pub(super) mod selected_reverse;
mod semantic;
mod source_facts;
pub(crate) mod source_publication;
pub(crate) mod source_storage;
mod structural;
use crate::analyzer::QueryToken;
use crate::analyzer::Range;
use crate::analyzer::store::LimitedQueryRows;
use crate::analyzer::{AnalyzerQueryScope, QueryScope};
pub use brokk_bifrost_jvm::java::structural::{
    JavaCallResultUse, JavaCallResultUseIndex, JavaCallResultUseOpen,
    JavaCallResultUseRelationIndex, java_call_result_use_site, java_plain_string_literal,
};

use crate::analyzer::clone_detection::detect_language_structural_clone_smells;
use crate::analyzer::common::{is_unparseable_source, language_for_file as file_language};
use crate::analyzer::languages::{
    DeadCodeBulkEdges, DeadCodeBulkPreflight, DeadCodeBulkProof, DeadCodeRouting, DeadCodeSupport,
    EdgePassId, EdgeSiteScanCtx, EdgeWeightScanCtx, LanguageEdgePass, LanguageEdgeSites,
    LanguageEdgeWeights, LanguageSupport, PatternBindingNameProvider, ProcedureSyntaxRoles,
    analyzable_file_count, build_fqn_bulk_edges, overloaded_function_fqns, package_fq_name,
    ready_preflight,
};
use crate::analyzer::loop_facts::{LoopKind, LoopSyntax};
use crate::analyzer::semantic::ProcedureKind;
use crate::analyzer::tree_sitter_analyzer::FileState;
use crate::analyzer::usages::java_graph::{
    JavaDeadCodeBulkEligibility, JavaUsageGraphStrategy, build_java_usage_edge_weights,
    build_java_usage_edges, build_rooted_java_usage_edges, dead_code_bulk_eligibility,
};
use crate::analyzer::usages::workspace_graph::UsageEcosystem;
use crate::analyzer::{
    AnalyzerConfig, AnalyzerStoreContext, BuildProgress, BuildProgressEvent, BulkFileStateSource,
    CloneSmell, CloneSmellWeights, CodeUnit, DeclarationKind, ExceptionHandlingAnalysis,
    ExceptionSmellWeights, ForwardQueryProvider, IAnalyzer, ImportAnalysisProvider, ImportInfo,
    Language, Project, ProjectFile, SignatureMetadata, TestAssertionSmell, TestAssertionWeights,
    TestDetectionProvider, TreeSitterAnalyzer, TypeHierarchyProvider, resolve_analyzer,
};
use crate::hash::{HashMap, HashSet};
use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use crate::analyzer::java::imports::JavaTypeResolution;
use crate::analyzer::jvm::dependency_discovery::is_jvm_dependency_input;
use crate::analyzer::jvm::external::{
    JvmExternalDeclarationIndex, JvmExternalDeclarations, jvm_external_qualified_name_exists,
};
use crate::analyzer::jvm::retained_external_index_state;
use crate::analyzer::structural::resolution::{BoundaryStatus, PrecedenceTier};
pub(crate) use adapter::JavaAdapter;
use brokk_bifrost_core::analyzer::prepared_syntax::PreparedSyntaxTree;
use brokk_bifrost_jvm::java::declarations::{
    find_nearest_declaration_from_node, is_comment_node, is_declaration_parent,
    is_java_anonymous_structure, node_text, normalize_java_full_name, parse_tree,
};
use brokk_bifrost_jvm::java::exceptions::detect_exception_handling_smells_java;
use brokk_bifrost_jvm::java::graph_support::{
    JavaConstructorContext, JavaSource, java_constructor_context, java_extract_type_identifiers,
    java_package_name_of, resolve_java_forward_type_name,
    resolve_java_forward_type_name_candidates,
};
use brokk_bifrost_jvm::java::imports::static_import_path;
use brokk_bifrost_jvm::java::structural::{
    java_parent_statement_body, java_switch_rule_value_expression_statement,
};
use brokk_bifrost_jvm::java::test_detection::detect_test_assertion_smells_java;
use brokk_bifrost_jvm::proof::JvmRetainedExternalIndex;
use cache::JavaMemoCaches;
use clones::build_clone_candidate_data;

#[derive(Clone)]
pub struct JavaAnalyzer {
    inner: TreeSitterAnalyzer<JavaAdapter>,
    memo_caches: Arc<JavaMemoCaches>,
    java_config: crate::analyzer::JvmAnalyzerConfig,
    pub(crate) external_index: Arc<std::sync::OnceLock<Arc<JvmExternalDeclarationIndex>>>,
}

crate::analyzer::impl_forward_query_provider!(JavaAnalyzer);

impl JavaAnalyzer {
    pub(crate) fn update_all_with_progress(&self, progress: Option<BuildProgress>) -> Self {
        Self {
            inner: self.inner.update_all_with_progress(progress),
            memo_caches: Arc::new(JavaMemoCaches::new(self.memo_caches.budget_bytes())),
            java_config: self.java_config.clone(),
            external_index: Arc::new(std::sync::OnceLock::new()),
        }
    }

    pub(crate) fn selected_jdk_home_for_file(
        &self,
        file: &ProjectFile,
    ) -> Result<&std::path::Path, crate::analyzer::JvmSourceToolchainSelectionOpen> {
        self.java_config
            .standard_library_discovery
            .selected_jdk_home_for_file(file)
    }

    #[cfg(test)]
    pub(crate) fn relational_batch_reader_checkouts_for_test(&self) -> usize {
        self.inner
            .analyzer_store()
            .relational_batch_counts_for_test()
            .0
    }

    #[cfg(any(test, debug_assertions))]
    #[doc(hidden)]
    pub fn reverse_import_indexes_ready_for_test(&self) -> (bool, bool) {
        (
            self.memo_caches.reverse_import_index.is_ready(),
            self.memo_caches.same_package_reference_index.is_ready(),
        )
    }

    pub(crate) fn clone_with_project(&self, project: Arc<dyn Project>) -> Self {
        let mut clone = self.clone();
        clone.inner = clone.inner.clone_with_project(project);
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
        let java_config = config.jvm.clone();
        TreeSitterAnalyzer::wrap_with_config(
            config,
            |config| TreeSitterAnalyzer::new_with_config(project, JavaAdapter, config),
            |inner, memo_budget| Self {
                inner,
                memo_caches: Arc::new(JavaMemoCaches::new(memo_budget)),
                java_config,
                external_index: Arc::new(std::sync::OnceLock::new()),
            },
        )
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
        let java_config = config.jvm.clone();
        TreeSitterAnalyzer::wrap_with_config(
            config,
            |config| {
                TreeSitterAnalyzer::new_with_config_and_progress(
                    project,
                    JavaAdapter,
                    config,
                    progress,
                )
            },
            |inner, memo_budget| Self {
                inner,
                memo_caches: Arc::new(JavaMemoCaches::new(memo_budget)),
                java_config,
                external_index: Arc::new(std::sync::OnceLock::new()),
            },
        )
    }

    pub(crate) fn new_with_config_store_context(
        project: Arc<dyn Project>,
        config: AnalyzerConfig,
        store_context: AnalyzerStoreContext,
        progress: Option<BuildProgress>,
    ) -> Result<Self, crate::analyzer::store::StoreError> {
        let java_config = config.jvm.clone();
        TreeSitterAnalyzer::try_wrap_with_config(
            config,
            |config| {
                TreeSitterAnalyzer::new_with_config_storage_context_and_progress(
                    project,
                    JavaAdapter,
                    config,
                    store_context,
                    progress,
                )
            },
            |inner, memo_budget| Self {
                inner,
                memo_caches: Arc::new(JavaMemoCaches::new(memo_budget)),
                java_config,
                external_index: Arc::new(std::sync::OnceLock::new()),
            },
        )
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
        token: QueryToken<'_>,
        file: &ProjectFile,
        raw_name: &str,
    ) -> Option<CodeUnit> {
        resolve_java_forward_type_name(self, token, file, raw_name)
    }

    /// Every candidate the deciding type-name tier produced for `raw_name`.
    /// More than one entry means colliding on-demand imports supplied the same
    /// simple name, so no candidate is provably unique (issue #1602).
    pub fn resolve_type_name_candidates_in_file(
        &self,
        token: QueryToken<'_>,
        file: &ProjectFile,
        raw_name: &str,
    ) -> Vec<CodeUnit> {
        resolve_java_forward_type_name_candidates(self, token, file, raw_name)
    }

    /// Whether `raw_name` names a type this file can see, in the workspace or
    /// past it. `packs` is the dispatching analyzer's activated overlay; see
    /// [`JavaAnalyzer::resolve_type_name_with_external`].
    pub fn is_known_type_name_in_file(
        &self,
        token: QueryToken<'_>,
        packs: Option<Arc<crate::analyzer::semantic_model::SemanticModelOverlay>>,
        file: &ProjectFile,
        raw_name: &str,
    ) -> bool {
        self.resolve_type_name_with_external(token, packs, file, raw_name)
            .is_some()
    }

    pub fn package_name_of(&self, file: &ProjectFile) -> Option<String> {
        java_package_name_of(self, file)
    }

    /// How far a lookup for `name` from `file` could see past the workspace,
    /// and the external declaration it landed on when it landed on one.
    ///
    /// This reads the external declaration surface that the resolver itself
    /// consults -- the jar index and the activated packs' declaration facts --
    /// and performs no new resolution, so it cannot change one. The three
    /// answers it distinguishes are the ones a single "unresolvable import"
    /// bucket cannot: the name is externally indexed, the build declared
    /// artifacts the index could not finish reading (so the name may be there),
    /// or nothing is known.
    ///
    /// A reference-site spelling is a type name or a member name, and both
    /// leave the workspace the same way: `Collections` names the type and
    /// `Collections.sort` names its member, so the member tier runs where the
    /// type tier found nothing (#1900). A member the surface does not declare
    /// changes nothing, so a type whose pack declares no members leaves every
    /// member spelling exactly as unknown as it was before activation.
    pub(crate) fn external_boundary_evidence(
        &self,
        token: QueryToken<'_>,
        packs: Option<Arc<crate::analyzer::semantic_model::SemanticModelOverlay>>,
        file: &ProjectFile,
        name: &str,
    ) -> (BoundaryStatus, Option<String>) {
        let type_evidence =
            match self.resolve_type_name_with_external(token, packs.clone(), file, name) {
                Some(JavaTypeResolution::External(external_type)) => {
                    crate::analyzer::languages::ExternalTypeBoundaryEvidence::Indexed(Some(
                        external_type.fqn().to_owned(),
                    ))
                }
                _ => crate::analyzer::languages::ExternalTypeBoundaryEvidence::Unresolved,
            };
        crate::analyzer::languages::classify_jvm_external_boundary_evidence(
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

    pub(crate) fn external_declaration_index(&self) -> &JvmExternalDeclarationIndex {
        crate::analyzer::jvm::external::get_or_build_external_declaration_index(
            &self.external_index,
            &self.java_config,
            self.inner.project(),
        )
    }

    /// The external declaration surface Java resolution reads: this analyzer's
    /// jar-backed index plus the declaration facts the activated semantic packs
    /// publish (#1893).
    pub(crate) fn external_declarations(
        &self,
        packs: Option<Arc<crate::analyzer::semantic_model::SemanticModelOverlay>>,
    ) -> JvmExternalDeclarations<'_> {
        JvmExternalDeclarations::new(self.external_declaration_index(), packs)
    }

    pub(crate) fn external_declarations_for_source_jdk(
        &self,
        packs: Option<Arc<crate::analyzer::semantic_model::SemanticModelOverlay>>,
        artifact_sha256: &str,
    ) -> JvmExternalDeclarations<'_> {
        self.external_declarations(packs)
            .select_jdk_artifact(artifact_sha256)
    }

    pub(crate) fn bulk_file_states(
        &self,
        files: impl IntoIterator<Item = ProjectFile>,
        source_mode: BulkFileStateSource,
    ) -> HashMap<ProjectFile, FileState> {
        self.inner.bulk_file_states(files, source_mode)
    }

    /// Classify exact-FQN callable candidates and the source-level constructor
    /// shape from one coherent indexed-facts query.
    pub(crate) fn constructor_context(
        &self,
        owner: &CodeUnit,
        candidates: Vec<CodeUnit>,
        call_arity: Option<usize>,
    ) -> Option<JavaConstructorContext> {
        let _scope = AnalyzerQueryScope::new(self);
        java_constructor_context(self, owner, candidates, call_arity)
    }
}

/// The analyzer-resident products the crate-side Java logic resolves through.
///
/// Every method forwards to one of this analyzer's own accessors or memo
/// cells, so the cells stay here and the free functions in
/// [`brokk_bifrost_jvm::java::graph_support`] cannot reach past this surface.
/// One file's class declarations by fq name, built once per request from the
/// in-memory declaration set (see `JavaSource::unique_class_by_fqn_in_file`).
struct JavaFileClassIndex {
    classes_by_fqn: HashMap<String, Vec<CodeUnit>>,
}

fn java_type_syntax_is_array(root: tree_sitter::Node<'_>) -> bool {
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if matches!(node.kind(), "array_type" | "dimensions") {
            return true;
        }
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }
    false
}

impl JavaFileClassIndex {
    fn build(declarations: BTreeSet<CodeUnit>) -> Self {
        let mut classes_by_fqn: HashMap<String, Vec<CodeUnit>> = HashMap::default();
        for unit in declarations.into_iter().filter(CodeUnit::is_class) {
            classes_by_fqn.entry(unit.fq_name()).or_default().push(unit);
        }
        Self { classes_by_fqn }
    }

    fn unique_class(&self, fqn: &str) -> brokk_bifrost_jvm::java::graph_support::UniqueClassInFile {
        let Some(units) = self.classes_by_fqn.get(fqn) else {
            return brokk_bifrost_jvm::java::graph_support::UniqueClassInFile::None;
        };
        brokk_bifrost_jvm::java::graph_support::unique_class_from_candidates(units.iter())
    }
}

#[derive(Default)]
struct JavaFileClassIndexMemo {
    by_file: Mutex<HashMap<ProjectFile, Arc<JavaFileClassIndex>>>,
}

impl JavaSource for JavaAnalyzer {
    fn declaration_source_facts(
        &self,
        _token: QueryToken<'_>,
        file: &ProjectFile,
    ) -> Option<Arc<brokk_bifrost_jvm::java::source_facts::JavaFileSourceFacts>> {
        self.inner
            .canonical_java_source_facts(file, &self.memo_caches.source_facts)
    }

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
        let scope = AnalyzerQueryScope::new(self);
        let token = scope.token();
        self.resolve_imports(token, file)
    }

    fn forward_definition_fqn(&self, fqn: &str) -> Vec<CodeUnit> {
        ForwardQueryProvider::forward_definition_fqn(self, fqn)
    }

    fn with_usage_definitions(
        &self,
        _token: QueryToken<'_>,
        read: &mut dyn FnMut(&dyn crate::analyzer::BoundedDefinitionLookup),
    ) {
        crate::analyzer::with_analyzer_usage_definitions(self, Language::Java, read);
    }

    fn unique_class_by_fqn_in_file(
        &self,
        fqn: &str,
        file: &ProjectFile,
    ) -> brokk_bifrost_jvm::java::graph_support::UniqueClassInFile {
        let memo = self
            .inner
            .active_query_request_memo::<JavaFileClassIndexMemo>();
        let index = match &memo {
            Some(memo) => {
                let cached = memo
                    .by_file
                    .lock()
                    .expect("Java file class index memo poisoned")
                    .get(file)
                    .cloned();
                match cached {
                    Some(index) => index,
                    None => {
                        let index =
                            Arc::new(JavaFileClassIndex::build(self.inner.declarations(file)));
                        memo.by_file
                            .lock()
                            .expect("Java file class index memo poisoned")
                            .entry(file.clone())
                            .or_insert_with(|| Arc::clone(&index))
                            .clone()
                    }
                }
            }
            None => Arc::new(JavaFileClassIndex::build(self.inner.declarations(file))),
        };
        index.unique_class(fqn)
    }

    fn source_types_in_packages(
        &self,
        _token: QueryToken<'_>,
        package_names: &[String],
    ) -> HashMap<String, Vec<CodeUnit>> {
        use crate::analyzer::{
            DefinitionLanguageScope, RelationalBatchOutcome, RelationalDefinitionQuery,
            RelationalDefinitionRequest, RelationalDefinitionValue,
        };
        use brokk_bifrost_core::analyzer::RelationalName;

        let unique = package_names.iter().collect::<BTreeSet<_>>();
        let requests = unique
            .iter()
            .enumerate()
            .map(|(ordinal, package)| RelationalDefinitionRequest {
                ordinal,
                language_scope: DefinitionLanguageScope::Language(Language::Java),
                name: RelationalName::stable(package_fq_name(Language::Java, package)),
                query: RelationalDefinitionQuery::PackageTypesInPackage,
            })
            .collect::<Vec<_>>();
        let outcome = self
            .relational_definition_batch(&requests, &crate::cancellation::CancellationToken::new());
        let RelationalBatchOutcome::Complete(results) = outcome else {
            if let RelationalBatchOutcome::Failed(error) = outcome {
                self.record_query_failure(crate::analyzer::store::StoreError::new(error.message()));
            }
            return HashMap::default();
        };
        let packages = unique.into_iter().cloned().collect::<Vec<_>>();
        assert_eq!(packages.len(), results.len());
        packages
            .into_iter()
            .zip(results)
            .map(|(package, result)| {
                let RelationalDefinitionValue::Definitions(types) = result.value else {
                    panic!("a Java package-types query returned the wrong shape")
                };
                (package, types)
            })
            .collect()
    }

    fn type_identifiers_of(&self, file: &ProjectFile) -> Option<HashSet<String>> {
        self.inner.type_identifiers_of(file)
    }

    crate::analyzer::tree_sitter_analyzer::delegate_inner_methods! {
        fn raw_supertypes_of(&self, code_unit: &CodeUnit) -> Vec<String>;
    }

    fn prepared_syntax(
        &self,
        token: QueryToken<'_>,
        file: &ProjectFile,
    ) -> Option<Arc<PreparedSyntaxTree>> {
        self.inner.prepared_syntax(token, file)
    }

    fn retained_external_index(&self) -> JvmRetainedExternalIndex {
        retained_external_index_state(self.external_index.get().map(Arc::as_ref))
    }

    fn retained_external_holds_qualified_name(&self, fqn: &str, access_package: &str) -> bool {
        self.external_index.get().is_some_and(|external| {
            jvm_external_qualified_name_exists(external, fqn, access_package)
        })
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
    crate::analyzer::tree_sitter_analyzer::delegate_inner_methods! {
        /// Forwarded so the request-scoped memo on the inner analyzer answers
        /// (#2679); the trait default would rebuild uncached per call.
        fn class_range_index(
        &self,
        file: &ProjectFile,
    ) -> std::sync::Arc<brokk_bifrost_core::analyzer::usages::inverted_edges::ClassRangeIndex>;
    }

    crate::analyzer::tree_sitter_analyzer::delegate_inner_methods! {
        fn enclosing_code_unit(
        &self,
        file: &ProjectFile,
        range: &crate::analyzer::Range,
    ) -> Option<CodeUnit>;
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

    fn all_declarations_with_primary_ranges(
        &self,
    ) -> Vec<(CodeUnit, Option<crate::analyzer::Range>)> {
        self.inner.all_declarations_with_primary_ranges()
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

    fn direct_children_in_file(&self, code_unit: &CodeUnit) -> Vec<CodeUnit> {
        self.inner.direct_children_in_file(code_unit)
    }

    fn parent_of(&self, code_unit: &CodeUnit) -> Option<CodeUnit> {
        self.inner.structural_parent_of(code_unit)
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
        self.inner.get_skeleton(code_unit)
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

impl IAnalyzer for JavaAnalyzer {
    crate::analyzer::tree_sitter_analyzer::delegate_inner_procedure_fact_methods!();

    crate::analyzer::i_analyzer::forward_relational_definition_batch!();

    #[cfg(any(test, feature = "test-support"))]
    fn test_hooks(&self) -> &dyn crate::analyzer::AnalyzerTestHooks {
        self
    }

    fn semantic_diagnostics(
        &self,
        file: &ProjectFile,
        source: &str,
    ) -> crate::analyzer::SemanticDiagnosticReport {
        let scope = AnalyzerQueryScope::new(self);
        diagnostics::collect_java_semantic_diagnostics(self, scope.token(), file, source)
    }

    /// Build the jar-backed external declaration index off the request path.
    ///
    /// #1615 forbids a diagnostic request from reading jars, so the proof-gated
    /// ladder peeks at this cell and calls an unbuilt one an unknown boundary.
    /// This is the hook that fills it: `IndexWarmer` runs it on a background
    /// thread for the generation, and the once-lock makes it idempotent.
    fn warm_query_indexes(&self) {
        self.external_declaration_index();
    }

    fn query_indexes_warm(&self) -> bool {
        self.external_index.get().is_some()
    }

    fn external_dispatch_behavior_identity(
        &self,
    ) -> Option<crate::analyzer::semantic::StableDigest> {
        Some(
            self.external_declaration_index()
                .dispatch_behavior_identity(),
        )
    }

    crate::analyzer::i_analyzer::forward_file_identity_invalidation!();

    fn working_tree_identity(&self) -> Option<std::sync::Arc<crate::gitblob::WorkingTreeIdentity>> {
        self.inner.working_tree_identity()
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

    fn declaration_syntax_kind(&self, code_unit: &CodeUnit) -> Option<&'static str> {
        self.inner.declaration_syntax_kind(code_unit)
    }

    crate::analyzer::tree_sitter_analyzer::delegate_inner_methods! {
        fn import_statements(&self, file: &ProjectFile) -> Vec<String>;
    }

    crate::analyzer::tree_sitter_analyzer::delegate_inner_methods! {
        fn compute_cognitive_complexities(&self, file: &ProjectFile) -> Vec<(CodeUnit, u32)>;
    }

    fn update(&self, changed_files: &BTreeSet<ProjectFile>) -> Self {
        let external_index = crate::analyzer::updated_external_index(
            &self.external_index,
            changed_files,
            is_jvm_dependency_input,
        );
        Self {
            inner: self.inner.update(changed_files),
            memo_caches: Arc::new(JavaMemoCaches::new(self.memo_caches.budget_bytes())),
            java_config: self.java_config.clone(),
            external_index,
        }
    }

    fn update_all(&self) -> Self {
        self.update_all_with_progress(None)
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

    fn parse_errors(&self, file: &ProjectFile) -> Option<Vec<crate::analyzer::ParseError>> {
        self.inner.parse_errors(file)
    }

    crate::analyzer::tree_sitter_analyzer::delegate_inner_methods! {
        fn extract_call_receiver(&self, reference: &str) -> Option<String>;
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

    crate::analyzer::tree_sitter_analyzer::delegate_inner_methods! {
        fn contains_tests(&self, file: &ProjectFile) -> bool;
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
        crate::analyzer::test_assertion_smells_for_file(self, file, Language::Java, |source| {
            detect_test_assertion_smells_java(self, file, source, &weights)
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
        detect_language_structural_clone_smells(self, files, weights, Language::Java, |code_unit| {
            build_clone_candidate_data(self, code_unit, weights)
        })
    }
}

#[cfg(any(test, feature = "test-support"))]
impl crate::analyzer::AnalyzerTestHooks for JavaAnalyzer {
    fn reset_java_usage_evidence_cache_stats_for_test(&self) {
        self.inner
            .test_hooks()
            .reset_java_usage_evidence_cache_stats_for_test();
    }

    fn java_usage_evidence_cache_stats_for_test(
        &self,
    ) -> crate::analyzer::JavaUsageEvidenceCacheStats {
        self.inner
            .test_hooks()
            .java_usage_evidence_cache_stats_for_test()
    }

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

    crate::analyzer::tree_sitter_analyzer::delegate_inner_test_hook_methods! {
        fn reset_package_declaration_scan_count_for_test(&self);
    }

    crate::analyzer::tree_sitter_analyzer::delegate_inner_test_hook_methods! {
        fn package_declaration_scan_count_for_test(&self) -> usize;
    }
}

static JAVA_USAGE_STRATEGY: JavaUsageGraphStrategy = JavaUsageGraphStrategy::new();

fn executable_statement_kind(node: tree_sitter::Node<'_>) -> Option<&'static str> {
    match node.kind() {
        "block" | "constructor_body" => Some("block"),
        "expression_statement" if java_switch_rule_value_expression_statement(node) => None,
        "expression_statement" => Some(
            if node
                .named_child(0)
                .is_some_and(|child| child.kind() == "switch_expression")
            {
                "switch"
            } else {
                "expression"
            },
        ),
        "local_variable_declaration"
            if !node
                .parent()
                .is_some_and(|parent| parent.kind() == "for_statement") =>
        {
            Some("local_declaration")
        }
        "explicit_constructor_invocation" => Some("constructor_invocation"),
        "return_statement" => Some("return"),
        "throw_statement" => Some("throw"),
        "yield_statement" => Some("yield"),
        "break_statement" => Some("break"),
        "continue_statement" => Some("continue"),
        "if_statement" => Some("if"),
        "while_statement" => Some("while"),
        "do_statement" => Some("do"),
        "for_statement" => Some("for"),
        "enhanced_for_statement" => Some("enhanced_for"),
        "switch_expression"
            if node
                .parent()
                .is_some_and(|parent| java_parent_statement_body(parent, node)) =>
        {
            Some("switch")
        }
        "try_statement" => Some("try"),
        "try_with_resources_statement" => Some("try_with_resources"),
        "synchronized_statement" => Some("synchronized"),
        "labeled_statement" => Some("labeled"),
        "assert_statement" => Some("assert"),
        "empty_statement" => Some("empty"),
        _ => None,
    }
}

fn java_loop_site(node: tree_sitter::Node<'_>) -> Option<LoopSyntax<'_>> {
    let kind = match node.kind() {
        "while_statement" => LoopKind::While,
        "for_statement" => LoopKind::For,
        "do_statement" => LoopKind::Do,
        _ => return None,
    };
    Some(LoopSyntax {
        kind,
        body: node.child_by_field_name("body"),
        condition: node.child_by_field_name("condition"),
    })
}

fn statement_procedure_matches(kind: ProcedureKind, node: tree_sitter::Node<'_>) -> bool {
    match kind {
        ProcedureKind::Method => node.kind() == "method_declaration",
        ProcedureKind::Constructor => matches!(
            node.kind(),
            "constructor_declaration" | "compact_constructor_declaration"
        ),
        ProcedureKind::Lambda => node.kind() == "lambda_expression",
        ProcedureKind::Initializer => matches!(
            node.kind(),
            "static_initializer" | "block" | "variable_declarator" | "enum_constant"
        ),
        _ => false,
    }
}

fn statement_nested_procedure(node: tree_sitter::Node<'_>) -> bool {
    matches!(
        node.kind(),
        "method_declaration"
            | "constructor_declaration"
            | "compact_constructor_declaration"
            | "lambda_expression"
            | "static_initializer"
            | "class_body"
            | "class_declaration"
            | "interface_declaration"
            | "enum_declaration"
            | "record_declaration"
            | "annotation_type_declaration"
    )
}

pub(crate) struct JavaSupport;

impl LanguageSupport for JavaSupport {
    #[cfg(any(test, feature = "test-support"))]
    fn native_rollout_points(
        &self,
    ) -> Option<&'static dyn crate::analyzer::languages::StructuralReceiverResolver> {
        Some(&crate::analyzer::jvm::native_points::JVM_NATIVE_ROLLOUT_POINTS)
    }

    fn is_configuration_input_path(&self, path: &std::path::Path) -> bool {
        crate::analyzer::jvm::is_jvm_configuration_input_path(path)
    }

    fn language(&self) -> Language {
        Language::Java
    }

    fn explicit_import_model_target(
        &self,
        analyzer: &dyn crate::analyzer::IAnalyzer,
        token: brokk_bifrost_core::analyzer::query_token::QueryToken<'_>,
        file: &crate::analyzer::ProjectFile,
        reference: &crate::analyzer::usages::reference_site::ResolvedReferenceSite,
    ) -> Option<String> {
        crate::analyzer::jvm::import_routes::explicit_import_model_route(
            analyzer, token, file, reference,
        )
        .map(|route| route.target)
    }

    fn call_applicability_adapter(
        &self,
    ) -> Option<&'static dyn crate::analyzer::resolution::CallApplicabilityAdapter> {
        Some(&call_applicability::JAVA_CALL_APPLICABILITY_ADAPTER)
    }

    fn procedure_syntax_roles(&self) -> Option<ProcedureSyntaxRoles> {
        Some(ProcedureSyntaxRoles {
            statement_kind: executable_statement_kind,
            loop_site: java_loop_site,
            loop_site_with_source: None,
            procedure_matches: statement_procedure_matches,
            nested_procedure: statement_nested_procedure,
        })
    }

    fn pattern_binding_name_provider(&self) -> Option<PatternBindingNameProvider> {
        Some(brokk_bifrost_jvm::java::structural::java_pattern_binding_name)
    }

    fn call_argument_conversion_prover(
        &self,
    ) -> Option<&'static dyn crate::analyzer::usages::call_conversion::CallArgumentConversionProver>
    {
        Some(&call_conversion::CALL_ARGUMENT_CONVERSION_PROVER)
    }

    fn expand_imported_external_callee(
        &self,
        analyzer: &dyn IAnalyzer,
        file: &ProjectFile,
        callee_text: &str,
        site: Option<&crate::analyzer::languages::ExternalCalleeSite<'_>>,
    ) -> Option<crate::analyzer::languages::ImportedExternalCallee> {
        let site = site?;
        crate::analyzer::usages::get_definition::java::expand_java_external_static_import_callee(
            analyzer,
            file,
            callee_text,
            site,
        )
    }

    /// Answers from `JavaAnalyzer::resolve_member_name_with_external` -- the
    /// same resolver #1900 built for "go to definition" and diagnostics,
    /// unmodified -- and claims a constant only when the resolved member is
    /// proven both `is_static()` and `is_compile_time_constant()` (#2538).
    fn external_compile_time_constant_member(
        &self,
        analyzer: &dyn IAnalyzer,
        file: &ProjectFile,
        spelling: &str,
    ) -> bool {
        let scope = AnalyzerQueryScope::new(analyzer);
        let Some(java) = resolve_analyzer::<JavaAnalyzer>(analyzer) else {
            return false;
        };
        java.resolve_member_name_with_external(
            scope.token(),
            analyzer.semantic_model_overlay(),
            file,
            spelling,
        )
        .is_some_and(|member| member.is_static() && member.is_compile_time_constant())
    }

    /// Answers from Java's checked-exception rules; see
    /// [`checked_exceptions::call_cannot_reach_catch_parameter`].
    fn call_cannot_reach_catch_parameter(
        &self,
        analyzer: &dyn IAnalyzer,
        file: &ProjectFile,
        source: &Arc<str>,
        call: std::ops::Range<usize>,
        catch_parameter: std::ops::Range<usize>,
    ) -> bool {
        checked_exceptions::call_cannot_reach_catch_parameter(
            analyzer,
            file,
            source,
            call,
            catch_parameter,
        )
    }

    /// Java keeps method names and variable names in separate namespaces (JLS
    /// 6.5.7): a local `int value = 7` does not shadow `value(item)`, and only
    /// the method-invocation path can say which overload the call reaches. A
    /// lexical binding answered for the callee name before the resolver ever
    /// ran, so a same-named local won the call site (#2046).
    fn focus_resolves_lexically(&self, focus: tree_sitter::Node<'_>) -> bool {
        !focus.parent().is_some_and(|parent| {
            parent.kind() == "method_invocation"
                && parent.child_by_field_name("name") == Some(focus)
        })
    }

    fn declaration_ranges_limited(
        &self,
        analyzer: &dyn IAnalyzer,
        unit: &CodeUnit,
        limit: usize,
    ) -> Option<LimitedQueryRows<Range>> {
        crate::analyzer::languages::with_resolved_analyzer::<JavaAnalyzer, _>(analyzer, |java| {
            java.inner().ranges_limited(unit, limit)
        })
    }

    fn signatures_limited(
        &self,
        analyzer: &dyn IAnalyzer,
        unit: &CodeUnit,
        limit: usize,
    ) -> Option<LimitedQueryRows<String>> {
        resolve_analyzer::<JavaAnalyzer>(analyzer)
            .map(|java| java.inner().signatures_limited(unit, limit))
    }

    fn forward_query_provider<'a>(
        &self,
        analyzer: &'a dyn IAnalyzer,
    ) -> Option<&'a dyn ForwardQueryProvider> {
        crate::analyzer::forward_query_provider::<JavaAnalyzer>(analyzer)
    }

    fn ecosystem(&self) -> UsageEcosystem {
        UsageEcosystem::Jvm
    }

    fn reference_usage_strategy(&self) -> &'static dyn crate::analyzer::usages::GraphUsageAnalyzer {
        &JAVA_USAGE_STRATEGY
    }

    fn reference_graph_backend(&self) -> crate::analyzer::languages::LanguageGraphBackend {
        crate::analyzer::languages::LanguageGraphBackend::Legacy(&JavaEdgePass)
    }

    fn dead_code(&self) -> DeadCodeSupport {
        DeadCodeSupport {
            strategy: Some(&JAVA_USAGE_STRATEGY),
            bulk: Some(&JavaDeadCodeBulk),
        }
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
        build_rooted_java_usage_edges(ctx.analyzer, ctx.fqns, ctx.keep_file)
            .map(LanguageEdgeSites::Fqn)
    }

    fn edge_weights(&self, ctx: &EdgeWeightScanCtx<'_>) -> Option<LanguageEdgeWeights> {
        build_java_usage_edge_weights(ctx.analyzer, ctx.fqns, ctx.keep_file)
            .map(LanguageEdgeWeights::Fqn)
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
        let scope = AnalyzerQueryScope::new(analyzer);
        let token = scope.token();
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
            && *static_imports_present
                .get_or_insert_with(|| java_static_imports_present(analyzer, token));
        let has_scala_files = *scala_files_present
            .get_or_insert_with(|| analyzable_file_count(analyzer, Language::Scala) > 0);

        matches!(
            dead_code_bulk_eligibility(
                analyzer,
                token,
                candidate,
                overloads,
                has_static_imports,
                has_scala_files,
            ),
            JavaDeadCodeBulkEligibility::NeedsPrecise
        )
    }

    fn preflight(&self, analyzer: &dyn IAnalyzer) -> DeadCodeBulkPreflight {
        ready_preflight(analyzer, Language::Java, "Java")
    }

    fn build(
        &self,
        analyzer: &dyn IAnalyzer,
        candidates: &[CodeUnit],
    ) -> Option<DeadCodeBulkEdges> {
        build_fqn_bulk_edges(analyzer, Language::Java, candidates, |analyzer, nodes| {
            build_java_usage_edges(analyzer, nodes, |_| true)
        })
    }
}

fn java_static_imports_present(analyzer: &dyn IAnalyzer, token: QueryToken<'_>) -> bool {
    let Ok(files) = analyzer.project().analyzable_files(Language::Java) else {
        return true;
    };
    files.into_iter().any(|file| {
        let Some(provider) = analyzer.import_analysis_provider_for_file(&file) else {
            return true;
        };
        provider
            .import_info_of(token, &file)
            .iter()
            .any(|import| import.path.is_none() || static_import_path(import).is_some())
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

    fn member_family(
        &self,
        member: &CodeUnit,
        cancellation: Option<&crate::cancellation::CancellationToken>,
    ) -> crate::analyzer::usages::MemberFamilyAnswer {
        crate::analyzer::usages::java_member_family(self, self, member, cancellation)
    }

    fn external_member_family(
        &self,
        identity: &brokk_bifrost_jvm::realm::JvmExternalMemberIdentity,
        max_visits: usize,
        cancellation: Option<&crate::cancellation::CancellationToken>,
    ) -> crate::analyzer::usages::ExternalMemberFamilyAnswer {
        self.resolve_external_member_family(self, identity, max_visits, cancellation)
    }
}
