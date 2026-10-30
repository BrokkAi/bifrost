#[doc(hidden)]
pub mod adapter;
mod annotation;

#[cfg(any(test, feature = "test-support"))]
use brokk_bifrost_analysis::delegate_inner_test_hook_methods;
use brokk_bifrost_analysis::{
    delegate_inner_methods, delegate_inner_procedure_fact_methods,
    forward_file_identity_invalidation, forward_relational_definition_batch,
    impl_forward_query_provider,
};

use crate::analyzer::java::source_facts::JavaSourceFacts;

pub use crate::analyzer::java::annotation::JavaAnnotationArtifact;
pub use crate::analyzer::java::annotation::JavaAnnotationTypeResolution;
pub use crate::analyzer::java::annotation::JavaAnnotationTypeRoute;

pub use crate::analyzer::java::annotation::JavaAnnotationTypeStatus;

pub use crate::analyzer::java::annotation::resolve_java_annotation_type;
mod cache;
mod call_applicability;
mod call_conversion;
mod workspace_facts;

pub use crate::analyzer::java::call_conversion::JavaLocalAssignmentConversionProver;

pub use crate::analyzer::java::call_conversion::JavaLocalAssignmentEvidence;
mod checked_exceptions;

pub(crate) use crate::analyzer::java::call_conversion::JavaFormalShape;

pub(crate) use crate::analyzer::java::call_conversion::declaration_declares_array;

pub(crate) use crate::analyzer::java::call_conversion::declared_type_node;

pub(crate) use crate::analyzer::java::call_conversion::formal_shapes;

pub(crate) use crate::analyzer::java::call_conversion::legacy_static_argument_type;

pub(crate) use crate::analyzer::java::call_conversion::parse_declaring_file;

pub(crate) use crate::analyzer::java::call_conversion::primitive_actual_type;

mod clones;
pub(crate) mod diagnostics;
mod hierarchy;
pub(crate) mod imports;
// Exercise the native consumer before the approved atomic JVM cutover.
#[cfg(any(test, feature = "test-support"))]
pub(super) mod native_call_relations;
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub mod native_points;
#[cfg(any(test, feature = "test-support"))]
pub(super) mod native_rename;
#[cfg(any(test, feature = "test-support"))]
pub(super) mod native_usages;
#[cfg(any(test, feature = "test-support"))]
pub(super) mod selected_reverse;
mod semantic;
#[doc(hidden)]
pub mod source_facts;
pub(crate) mod source_publication;
#[doc(hidden)]
pub mod source_storage;
mod structural;

use brokk_bifrost_core::analyzer::query_token::QueryToken;

use brokk_bifrost_core::analyzer::model::Range;

use brokk_bifrost_core::analyzer::query_batch::LimitedQueryRows;

use brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope;

use brokk_bifrost_core::analyzer::query_token::QueryScope;
pub use brokk_bifrost_jvm::java::structural::{
    JavaCallResultUse, JavaCallResultUseIndex, JavaCallResultUseOpen,
    JavaCallResultUseRelationIndex, java_call_result_use_site, java_plain_string_literal,
};

use brokk_bifrost_analysis::analyzer::clone_detection::detect_language_structural_clone_smells;

use brokk_bifrost_core::analyzer::common::is_unparseable_source;

use brokk_bifrost_core::analyzer::common::language_for_file as file_language;

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

use brokk_bifrost_analysis::analyzer::languages::PatternBindingNameProvider;

use brokk_bifrost_analysis::analyzer::languages::ProcedureSyntaxRoles;

use brokk_bifrost_analysis::analyzer::languages::analyzable_file_count;

use brokk_bifrost_analysis::analyzer::languages::build_fqn_bulk_edges;

use brokk_bifrost_analysis::analyzer::languages::overloaded_function_fqns;

use brokk_bifrost_analysis::analyzer::languages::package_fq_name;

use brokk_bifrost_analysis::analyzer::languages::ready_preflight;

use brokk_bifrost_analysis::analyzer::loop_facts::LoopKind;

use brokk_bifrost_analysis::analyzer::loop_facts::LoopSyntax;

use brokk_bifrost_semantic::analyzer::semantic::ir::ProcedureKind;

use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::FileState;

use crate::analyzer::usages::java_graph::JavaDeadCodeBulkEligibility;

use crate::analyzer::usages::java_graph::JavaUsageGraphStrategy;

use crate::analyzer::usages::java_graph::build_java_usage_edge_weights;

use crate::analyzer::usages::java_graph::build_java_usage_edges;

use crate::analyzer::usages::java_graph::build_rooted_java_usage_edges;

use crate::analyzer::usages::java_graph::dead_code_bulk_eligibility;

use brokk_bifrost_analysis::analyzer::usages::workspace_graph::UsageEcosystem;

use brokk_bifrost_core::analyzer::config::AnalyzerConfig;

use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::AnalyzerStoreContext;

use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::BuildProgress;

use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::BuildProgressEvent;

use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::BulkFileStateSource;

use brokk_bifrost_core::analyzer::model::CloneSmell;

use brokk_bifrost_core::analyzer::model::CloneSmellWeights;

use brokk_bifrost_core::analyzer::model::CodeUnit;

use brokk_bifrost_core::analyzer::model::DeclarationKind;

use brokk_bifrost_core::analyzer::model::ExceptionHandlingAnalysis;

use brokk_bifrost_core::analyzer::model::ExceptionSmellWeights;

use brokk_bifrost_analysis::analyzer::analyzer_definition_lookup::ForwardQueryProvider;

use brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer;

use brokk_bifrost_core::analyzer::capabilities::ImportAnalysisProvider;

use brokk_bifrost_core::analyzer::model::ImportInfo;

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
use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use crate::analyzer::java::imports::JavaTypeResolution;

use crate::analyzer::jvm::dependency_discovery::is_jvm_dependency_input;

use crate::analyzer::jvm::external::JvmExternalDeclarationIndex;

use crate::analyzer::jvm::external::JvmExternalDeclarations;

use crate::analyzer::jvm::external::jvm_external_qualified_name_exists;

use brokk_bifrost_core::analyzer::structural::resolution::BoundaryStatus;

use brokk_bifrost_core::analyzer::structural::resolution::PrecedenceTier;

pub(crate) use crate::analyzer::java::adapter::JavaAdapter;
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

use crate::analyzer::java::cache::JavaMemoCaches;
use brokk_bifrost_analysis::analyzer::{WorkspaceAuthorityMemo, WorkspaceFactFamily};

type JavaImportInventoryMemo = WorkspaceAuthorityMemo<
    brokk_bifrost_analysis::analyzer::common::QueryCacheCell<
        brokk_bifrost_analysis::analyzer::common::ReplayableQueryCacheValue<
            brokk_bifrost_analysis::analyzer::semantic::StableDigest,
        >,
    >,
>;

fn fresh_import_inventory() -> Arc<JavaImportInventoryMemo> {
    Arc::new(WorkspaceAuthorityMemo::new(
        WorkspaceFactFamily::JavaImportInventory,
        brokk_bifrost_analysis::analyzer::common::QueryCacheCell::new(),
    ))
}

use crate::analyzer::java::clones::build_clone_candidate_data;

#[derive(Clone)]
pub struct JavaAnalyzer {
    inner: TreeSitterAnalyzer<JavaAdapter>,
    memo_caches: Arc<JavaMemoCaches>,
    // The inventory covers both source and external declarations. Its lifetime
    // must end whenever either input is renewed, including overlay clones.
    import_inventory: Arc<JavaImportInventoryMemo>,
    java_config: brokk_bifrost_core::analyzer::config::JvmAnalyzerConfig,
    pub(crate) external_index: Arc<
        brokk_bifrost_analysis::analyzer::common::QueryCacheCell<
            brokk_bifrost_analysis::analyzer::common::ReplayableQueryCacheValue<
                Arc<JvmExternalDeclarationIndex>,
            >,
        >,
    >,
    external_inputs: crate::analyzer::jvm::hierarchy::DerivedMemo<(), ()>,
}

impl_forward_query_provider!(JavaAnalyzer);

impl JavaAnalyzer {
    pub(crate) fn read_capability(
        &self,
    ) -> brokk_bifrost_core::analyzer::project_reads::ReadCapability {
        self.inner.read_capability()
    }

    pub(crate) fn update_all_with_progress(&self, progress: Option<BuildProgress>) -> Self {
        brokk_bifrost_core::analyzer::project_reads::without_project_reads(|| Self {
            inner: self.inner.update_all_with_progress(progress),
            memo_caches: Arc::new(JavaMemoCaches::new(self.memo_caches.budget_bytes())),
            import_inventory: fresh_import_inventory(),
            java_config: self.java_config.clone(),
            external_index: Arc::new(
                brokk_bifrost_analysis::analyzer::common::QueryCacheCell::new(),
            ),
            external_inputs: crate::analyzer::jvm::hierarchy::derived_memo(
                self.memo_caches.budget_bytes() / 8,
            ),
        })
    }

    pub(crate) fn selected_jdk_home_for_file(
        &self,
        file: &ProjectFile,
    ) -> Result<
        &std::path::Path,
        brokk_bifrost_core::analyzer::config::JvmSourceToolchainSelectionOpen,
    > {
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

    // Integration tests also use the measure profile, without debug assertions.
    #[cfg(any(test, debug_assertions, feature = "test-support"))]
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
        clone.import_inventory = fresh_import_inventory();
        clone.external_index =
            Arc::new(brokk_bifrost_analysis::analyzer::common::QueryCacheCell::new());
        clone.external_inputs =
            crate::analyzer::jvm::hierarchy::derived_memo(self.memo_caches.budget_bytes() / 8);
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
                import_inventory: fresh_import_inventory(),
                java_config,
                external_index: Arc::new(
                    brokk_bifrost_analysis::analyzer::common::QueryCacheCell::new(),
                ),
                external_inputs: crate::analyzer::jvm::hierarchy::derived_memo(memo_budget / 8),
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
                import_inventory: fresh_import_inventory(),
                java_config,
                external_index: Arc::new(
                    brokk_bifrost_analysis::analyzer::common::QueryCacheCell::new(),
                ),
                external_inputs: crate::analyzer::jvm::hierarchy::derived_memo(memo_budget / 8),
            },
        )
    }

    #[doc(hidden)]
    pub fn new_with_config_store_context(
        project: Arc<dyn Project>,
        config: AnalyzerConfig,
        store_context: AnalyzerStoreContext,
        progress: Option<BuildProgress>,
    ) -> Result<Self, brokk_bifrost_analysis::analyzer::store::StoreError> {
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
                import_inventory: fresh_import_inventory(),
                java_config,
                external_index: Arc::new(
                    brokk_bifrost_analysis::analyzer::common::QueryCacheCell::new(),
                ),
                external_inputs: crate::analyzer::jvm::hierarchy::derived_memo(memo_budget / 8),
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
        packs: Option<
            Arc<brokk_bifrost_analysis::analyzer::semantic_model::overlay::SemanticModelOverlay>,
        >,
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
        packs: Option<
            Arc<brokk_bifrost_analysis::analyzer::semantic_model::overlay::SemanticModelOverlay>,
        >,
        file: &ProjectFile,
        name: &str,
    ) -> (BoundaryStatus, Option<String>) {
        let type_evidence =
            match self.resolve_type_name_with_external(token, packs.clone(), file, name) {
                Some(JavaTypeResolution::External(external_type)) => {
                    brokk_bifrost_analysis::analyzer::languages::ExternalTypeBoundaryEvidence::Indexed(Some(
                        external_type.fqn().to_owned(),
                    ))
                }
                _ => brokk_bifrost_analysis::analyzer::languages::ExternalTypeBoundaryEvidence::Unresolved,
            };
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

    pub(crate) fn external_declaration_index(&self) -> Arc<JvmExternalDeclarationIndex> {
        crate::analyzer::jvm::external::get_or_build_external_declaration_index(
            self,
            &self.external_index,
            (
                Language::Java,
                brokk_bifrost_analysis::analyzer::WorkspaceFactFamily::JavaExternalDeclarations,
            ),
            &self.external_inputs,
            &self.java_config,
            self.inner.project(),
            self.inner.analyzer_store(),
        )
    }

    /// The external declaration surface Java resolution reads: this analyzer's
    /// jar-backed index plus the declaration facts the activated semantic packs
    /// publish (#1893).
    pub(crate) fn external_declarations(
        &self,
        packs: Option<
            Arc<brokk_bifrost_analysis::analyzer::semantic_model::overlay::SemanticModelOverlay>,
        >,
    ) -> JvmExternalDeclarations<'_> {
        JvmExternalDeclarations::new(self.external_declaration_index(), packs)
    }

    pub(crate) fn external_declarations_for_source_jdk(
        &self,
        packs: Option<
            Arc<brokk_bifrost_analysis::analyzer::semantic_model::overlay::SemanticModelOverlay>,
        >,
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
    fn resolve_imported_type_name(
        &self,
        token: QueryToken<'_>,
        file: &ProjectFile,
        raw_name: &str,
    ) -> Option<CodeUnit> {
        workspace_facts::imported_type_name(self, token, file, raw_name)
    }

    fn import_inventory_is_complete(&self) -> bool {
        // Plain lookups need the completeness bit, not its full certificate.
        if brokk_bifrost_analysis::analyzer::workspace_authority::memo_attribution(self)
            .is_capturing()
        {
            self.import_inventory_answer();
        }
        self.has_complete_symbol_lookup_index()
    }

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
        if let Some(reader) = self.inner.canonical_source_read(file, "java") {
            reader.record_read_key();
        }
        let cache_fill = brokk_bifrost_analysis::analyzer::common::QueryCacheFill::new(self);

        if let Some(package) = self.memo_caches.package_names.get(file) {
            return Some(package);
        }
        let package: Arc<str> = Arc::from(self.inner.package_name_of(file)?);
        {
            let cache_key = file.clone();
            let cache_value = Arc::clone(&package);
            if cache_fill.is_complete() {
                self.memo_caches
                    .package_names
                    .insert(cache_key, cache_value);
            }
        };
        Some(package)
    }

    fn resolved_imports(&self, file: &ProjectFile) -> Arc<HashMap<String, CodeUnit>> {
        let scope = AnalyzerQueryScope::new(self);
        let token = scope.token();
        self.resolve_imports(token, file)
    }

    fn forward_definition_fqn(&self, fqn: &str) -> Vec<CodeUnit> {
        self.workspace_classes(fqn)
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
            Language::Java,
            read,
        );
    }

    fn unique_class_by_fqn_in_file(
        &self,
        fqn: &str,
        file: &ProjectFile,
    ) -> brokk_bifrost_jvm::java::graph_support::UniqueClassInFile {
        // This hot file-only index is cheaper to certify directly than to
        // allocate and replay one receipt for every same-file class question.
        if let Some(reader) = self.inner.canonical_source_read(file, "java") {
            reader.record_read_key();
        }
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
        use brokk_bifrost_core::analyzer::definition_lookup::DefinitionLanguageScope;

        use brokk_bifrost_core::analyzer::definition_lookup::RelationalBatchOutcome;

        use brokk_bifrost_core::analyzer::definition_lookup::RelationalDefinitionQuery;

        use brokk_bifrost_core::analyzer::definition_lookup::RelationalDefinitionRequest;

        use brokk_bifrost_core::analyzer::RelationalName;
        use brokk_bifrost_core::analyzer::definition_lookup::RelationalDefinitionValue;

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
        let outcome = self.relational_definition_batch(
            &requests,
            &brokk_bifrost_core::cancellation::CancellationToken::new(),
        );
        let RelationalBatchOutcome::Complete(results) = outcome else {
            if let RelationalBatchOutcome::Failed(error) = outcome {
                self.record_query_failure(
                    brokk_bifrost_analysis::analyzer::store::StoreError::new(error.message()),
                );
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

    delegate_inner_methods! {
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
        crate::analyzer::jvm::authority::retained_external_index(
            self,
            &self.external_index,
            &self.external_inputs,
        )
    }

    fn retained_external_holds_qualified_name(&self, fqn: &str, access_package: &str) -> bool {
        crate::analyzer::jvm::authority::external_read(
            self,
            &self.external_index,
            &self.external_inputs,
        );
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

use brokk_bifrost_core::analyzer::code_unit_index::CodeUnitIndex;

impl CodeUnitIndex for JavaAnalyzer {
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

    fn all_declarations_with_primary_ranges(
        &self,
    ) -> Vec<(CodeUnit, Option<brokk_bifrost_core::analyzer::model::Range>)> {
        self.inner.all_declarations_with_primary_ranges()
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

    fn direct_children_in_file(&self, code_unit: &CodeUnit) -> Vec<CodeUnit> {
        self.inner.direct_children_in_file(code_unit)
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
        self.inner.lookup_declarations_by_identifier(identifier)
    }
}

impl IAnalyzer for JavaAnalyzer {
    fn statement_source_facts(
        &self,
        file: &ProjectFile,
    ) -> Option<Arc<brokk_bifrost_core::analyzer::statement_facts::StatementFactRows>> {
        use brokk_bifrost_analysis::analyzer::structural::lexical_environment::{
            BindingOfOutcome, binding_of, environment_for_file,
        };
        use brokk_bifrost_core::analyzer::statement_facts::producer::{
            StatementFacts, capture_statement_facts,
        };
        use brokk_bifrost_core::analyzer::structural::occurrences::Namespace;
        use brokk_bifrost_jvm::java::structural::JAVA_STRUCTURAL_SPEC;
        let source = self.inner.file_source(file)?;
        let oid = git2::Oid::hash_object(git2::ObjectType::Blob, source.as_bytes())
            .expect("source blob hash");
        let key = (oid, file.clone());
        let result = self.memo_caches.statement_facts.read(
            &brokk_bifrost_analysis::analyzer::workspace_authority::memo_attribution(self),
            |cache, capture| {
                if let Some(rows) = cache.get(&key) {
                    return Ok::<_, ()>(rows);
                }
                let mut cacheable = false;
                let entry = Arc::new(capture.try_build_weighted(|| {
        let scope = AnalyzerQueryScope::capturing_read_incompleteness(self);
        let tree = parse_tree(&source).ok_or(())?;
        let root = tree.root_node();
        let mut rows = capture_statement_facts(&JAVA_STRUCTURAL_SPEC, root, &source);
        if !rows.switches.is_empty() {
            let environment = environment_for_file(self, file);
            let support = brokk_bifrost_analysis::analyzer::analyzer_definition_lookup::AnalyzerDefinitionLookup::new(self, Language::Java);
            let session =
                crate::analyzer::usages::get_definition::java::JavaResolutionSession::unbounded(
                    &support,
                );
            let lookup = |name: tree_sitter::Node<'_>, namespace| {
                let text = name.utf8_text(source.as_bytes()).ok()?;
                let binding =
                    match binding_of(&environment, text, name.start_byte(), Some(namespace)) {
                        BindingOfOutcome::Reached(binding)
                        | BindingOfOutcome::Shadowed {
                            winner: binding, ..
                        } => binding,
                        BindingOfOutcome::NoBinding | BindingOfOutcome::Incomplete(_) => {
                            return None;
                        }
                    };
                let range = environment.bindings[binding].range;
                root.named_descendant_for_byte_range(range.start_byte, range.end_byte)
            };
            let producer =
                StatementFacts::new(&JAVA_STRUCTURAL_SPEC).expect("Java statement syntax");
            // Bind values through the shared lexical environment and types
            // through Java's existing context-aware resolver. Only an enum
            // declaration in this source snapshot supplies a local proof.
            let switches: Vec<_> = rows.switches.iter().map(|switch| switch.range).collect();
            for range in switches {
                let Some(switch) =
                    root.named_descendant_for_byte_range(range.start_byte, range.end_byte)
                else {
                    continue;
                };
                let Some(operand) = switch
                    .child_by_field_name("condition")
                    .map(brokk_bifrost_core::analyzer::tree_walk::unwrap_parenthesized_expression)
                else {
                    continue;
                };
                if operand.kind() != "identifier" {
                    continue;
                }
                let Some(binder) = lookup(operand, Namespace::Value) else {
                    continue;
                };
                let Some(type_node) = binder.parent().and_then(declared_type_node) else {
                    continue;
                };
                if type_node.kind() != "type_identifier" {
                    continue;
                }
                let Some(unit) = crate::analyzer::usages::get_definition::java::java_type_from_node_with_context(
                    self, scope.token(), self, &session, file, &source, type_node,
                ).filter(|unit| unit.source() == file) else { continue; };
                let Some(enumeration) = self
                    .ranges(&unit)
                    .into_iter()
                    .filter_map(|range| {
                        root.named_descendant_for_byte_range(range.start_byte, range.end_byte)
                    })
                    .find(|node| node.kind() == "enum_declaration")
                else {
                    continue;
                };
                producer.complete_enum_switch(switch, enumeration, &source, &mut rows);
            }
        }
        let rows = Arc::new(rows);
                    cacheable = scope.captured_read_incompleteness().is_empty();
                    let bytes = rows.estimated_retained_bytes()
                        + brokk_bifrost_analysis::analyzer::cache_weight::estimate_project_file(file) as usize;
                    Ok::<_, ()>((rows, bytes))
                })?);
                // Keep the existing complete-build-only admission rule.
                if cacheable {
                    cache.insert(key, Arc::clone(&entry));
                }
                Ok(entry)
            },
        ).ok()?;
        Some(Arc::clone(&result))
    }

    delegate_inner_procedure_fact_methods!();

    forward_relational_definition_batch!();

    #[cfg(any(test, feature = "test-support"))]
    fn test_hooks(&self) -> &dyn brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerTestHooks {
        self
    }

    fn semantic_diagnostics(
        &self,
        file: &ProjectFile,
        source: &str,
    ) -> brokk_bifrost_core::analyzer::model::SemanticDiagnosticReport {
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
    ) -> Option<brokk_bifrost_analysis::analyzer::semantic::StableDigest> {
        Some(
            self.external_declaration_index()
                .dispatch_behavior_identity(),
        )
    }

    forward_file_identity_invalidation!();

    fn working_tree_identity(
        &self,
    ) -> Option<std::sync::Arc<brokk_bifrost_core::gitblob::WorkingTreeIdentity>> {
        self.inner.working_tree_identity()
    }

    brokk_bifrost_analysis::forward_query_read_ledger!();

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

    fn declaration_syntax_kind(&self, code_unit: &CodeUnit) -> Option<&'static str> {
        self.inner.declaration_syntax_kind(code_unit)
    }

    delegate_inner_methods! {
        fn import_statements(&self, file: &ProjectFile) -> Vec<String>;
    }

    delegate_inner_methods! {
        fn compute_cognitive_complexities(&self, file: &ProjectFile) -> Vec<(CodeUnit, u32)>;
    }

    fn update(&self, changed_files: &BTreeSet<ProjectFile>) -> Self {
        brokk_bifrost_core::analyzer::project_reads::without_project_reads(|| {
            let external_index = brokk_bifrost_analysis::analyzer::updated_external_index(
                &self.external_index,
                changed_files,
                is_jvm_dependency_input,
            );
            Self {
                inner: self.inner.update(changed_files),
                memo_caches: Arc::new(JavaMemoCaches::new(self.memo_caches.budget_bytes())),
                import_inventory: fresh_import_inventory(),
                java_config: self.java_config.clone(),
                external_index,
                external_inputs: crate::analyzer::jvm::hierarchy::derived_memo(
                    self.memo_caches.budget_bytes() / 8,
                ),
            }
        })
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

    fn member_family_provider(
        &self,
    ) -> Option<&dyn brokk_bifrost_analysis::analyzer::usages::member_family::MemberFamilyProvider>
    {
        Some(self)
    }

    fn test_detection_provider(&self) -> Option<&dyn TestDetectionProvider> {
        Some(self)
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

    fn parse_errors(
        &self,
        file: &ProjectFile,
    ) -> Option<Vec<brokk_bifrost_core::analyzer::model::ParseError>> {
        self.inner.parse_errors(file)
    }

    delegate_inner_methods! {
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
    ) -> Option<brokk_bifrost_core::analyzer::model::DeclarationInfo> {
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
        patterns: &brokk_bifrost_analysis::analyzer::i_analyzer::SearchSymbolPatternBatch,
        cancellation: Option<&brokk_bifrost_core::cancellation::CancellationToken>,
    ) -> brokk_bifrost_analysis::analyzer::i_analyzer::SearchSymbolCandidates {
        self.inner.search_symbol_candidates(patterns, cancellation)
    }

    delegate_inner_methods! {
        fn contains_tests(&self, file: &ProjectFile) -> bool;
    }

    fn in_test_region(&self, code_unit: &brokk_bifrost_core::analyzer::model::CodeUnit) -> bool {
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
        brokk_bifrost_analysis::analyzer::test_assertion_smells_for_file(
            self,
            file,
            Language::Java,
            |source| detect_test_assertion_smells_java(self, file, source, &weights),
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
        detect_language_structural_clone_smells(self, files, weights, Language::Java, |code_unit| {
            build_clone_candidate_data(self, code_unit, weights)
        })
    }
}

#[cfg(any(test, feature = "test-support"))]
impl brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerTestHooks for JavaAnalyzer {
    fn reset_java_usage_evidence_cache_stats_for_test(&self) {
        self.inner
            .test_hooks()
            .reset_java_usage_evidence_cache_stats_for_test();
    }

    fn java_usage_evidence_cache_stats_for_test(
        &self,
    ) -> brokk_bifrost_analysis::analyzer::usages::java_usage_evidence_cache::JavaUsageEvidenceCacheStats{
        self.inner
            .test_hooks()
            .java_usage_evidence_cache_stats_for_test()
    }

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
        fn reset_package_declaration_scan_count_for_test(&self);
    }

    delegate_inner_test_hook_methods! {
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

impl brokk_bifrost_analysis::analyzer::multi_analyzer::LanguageAnalyzer for JavaAnalyzer {
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
        Box::new(JavaAnalyzer::clone_with_project(self, project))
    }

    fn clone_for_index_warm(
        &self,
        project: Arc<dyn Project>,
    ) -> Box<dyn brokk_bifrost_analysis::analyzer::multi_analyzer::LanguageAnalyzer> {
        Box::new(JavaAnalyzer::clone_for_index_warm(self, project))
    }

    fn import_analysis_provider(&self) -> Option<&dyn ImportAnalysisProvider> {
        Some(self)
    }

    fn type_hierarchy_provider(
        &self,
    ) -> Option<&dyn brokk_bifrost_core::analyzer::capabilities::TypeHierarchyProvider> {
        Some(self)
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
        Box::new(JavaAnalyzer::update_all_with_progress(self, progress))
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
pub struct JavaSupport;

fn java_branch_reference_site(
    node: tree_sitter::Node<'_>,
) -> Option<brokk_bifrost_analysis::analyzer::structural::branch_relations::BranchReferenceSite> {
    use brokk_bifrost_analysis::analyzer::structural::branch_relations::{
        BranchReferenceKind, BranchReferenceSite,
    };
    let (focus, kind) = match node.kind() {
        "method_invocation" => (
            node.child_by_field_name("name")?,
            BranchReferenceKind::Method,
        ),
        "field_access" => (
            node.child_by_field_name("field")?,
            BranchReferenceKind::Field,
        ),
        "identifier"
            if node.parent().is_some_and(|parent| {
                parent.kind() == "method_invocation"
                    && parent.child_by_field_name("name") == Some(node)
            }) =>
        {
            return None;
        }
        "identifier" => (node, BranchReferenceKind::Field),
        _ => return None,
    };
    Some(BranchReferenceSite {
        range: (focus.start_byte(), focus.end_byte()),
        kind,
    })
}

impl LanguageSupport for JavaSupport {
    fn workspace_fact_answer(
        &self,
        analyzer: &dyn IAnalyzer,
        family: brokk_bifrost_analysis::analyzer::WorkspaceFactFamily,
        language: Language,
        subject: &brokk_bifrost_analysis::analyzer::FactSubject,
    ) -> Option<brokk_bifrost_analysis::analyzer::semantic::StableDigest> {
        workspace_facts::answer(analyzer, family, language, subject)
    }

    #[cfg(any(test, feature = "test-support"))]
    fn observed_value_type(
        &self,
        analyzer: &dyn IAnalyzer,
        observation: &brokk_bifrost_analysis::analyzer::semantic::BarrierObservation,
        request: &mut brokk_bifrost_analysis::analyzer::semantic::SemanticRequest<'_>,
    ) -> Result<
        brokk_bifrost_analysis::analyzer::semantic::ObservedValueType,
        brokk_bifrost_analysis::analyzer::semantic::SemanticProviderError,
    > {
        native_points::observed_value_type(analyzer, observation, request)
    }

    fn branch_body_reference_site(
        &self,
        node: tree_sitter::Node<'_>,
        _source: &str,
    ) -> Option<brokk_bifrost_analysis::analyzer::structural::branch_relations::BranchReferenceSite>
    {
        java_branch_reference_site(node)
    }

    fn branch_condition_reference_site(
        &self,
        node: tree_sitter::Node<'_>,
        _source: &str,
    ) -> Option<brokk_bifrost_analysis::analyzer::structural::branch_relations::BranchReferenceSite>
    {
        java_branch_reference_site(node)
    }

    fn supports_selected_resolution_overlays(&self) -> bool {
        true
    }

    fn formal_parameter_owner_kinds(&self) -> Option<&'static [&'static str]> {
        Some(&[
            "method_declaration",
            "constructor_declaration",
            "compact_constructor_declaration",
            "record_declaration",
        ])
    }

    fn formal_parameter_source_owner<'tree>(
        &self,
        owner: tree_sitter::Node<'tree>,
        scope_step: &mut dyn FnMut() -> bool,
    ) -> Option<tree_sitter::Node<'tree>> {
        if owner.kind() != "compact_constructor_declaration" {
            return Some(owner);
        }
        if !scope_step() {
            return None;
        }
        let body = owner.parent();
        if !scope_step() {
            return None;
        }
        // Parser recovery can put a compact constructor outside a record.
        // It has no inherited header; only budget exhaustion stops traversal.
        Some(
            body.and_then(|body| body.parent())
                .filter(|record| record.kind() == "record_declaration")
                .unwrap_or(owner),
        )
    }

    fn parameter_owner_has_lexical_bindings(&self, owner: tree_sitter::Node<'_>) -> bool {
        // JLS 8.10.4: only the canonical constructor owns these parameters.
        owner.kind() != "record_declaration"
    }

    fn implicit_callable_parameter_layout(
        &self,
        unit: &CodeUnit,
        root: tree_sitter::Node<'_>,
        source: &str,
        range: &Range,
    ) -> Option<brokk_bifrost_analysis::analyzer::lexical_definitions::FormalParameterLayout> {
        use brokk_bifrost_core::analyzer::tree_walk::node_for_exact_range;
        use brokk_bifrost_jvm::java::declarations::{
            java_record_components, java_record_declares_accessor,
        };
        if !unit.is_callable() {
            return None;
        }
        let node = node_for_exact_range(root, range)?;
        let parameters = node.parent()?;
        let record = parameters.parent()?;
        if parameters.kind() != "formal_parameters" || record.kind() != "record_declaration" {
            return None;
        }
        let components = java_record_components(parameters).ok()?;
        let component = components.iter().find(|component| component.node == node)?;
        let name = brokk_bifrost_jvm::java::declarations::node_text(component.name, source);
        if unit.identifier() != name || java_record_declares_accessor(record, name, source) {
            return None;
        }
        Some(
            brokk_bifrost_analysis::analyzer::lexical_definitions::FormalParameterLayout {
                slots: Vec::new(),
                python_binding: None,
            },
        )
    }

    fn analyze_receiver_query(
        &self,
        service: &brokk_bifrost_analysis::analyzer::usages::receiver_query::ReceiverQueryService<
            '_,
        >,
        operation: brokk_bifrost_analysis::analyzer::usages::receiver_query::ReceiverQueryOperation,
        file: &ProjectFile,
        range: Range,
        input: brokk_bifrost_analysis::analyzer::usages::receiver_query::ReceiverQueryInput,
        budget: brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverAnalysisBudget,
        cancellation: Option<&brokk_bifrost_core::cancellation::CancellationToken>,
        indexed_source: Option<String>,
    ) -> Option<
        Result<
            brokk_bifrost_analysis::analyzer::usages::receiver_query::ReceiverQueryReport,
            brokk_bifrost_analysis::analyzer::usages::receiver_query::ReceiverQueryError,
        >,
    > {
        use crate::analyzer::java::receiver_query::JavaReceiverQueryService;
        Some(service.analyze_java(
            operation,
            file,
            range,
            input,
            budget,
            cancellation,
            indexed_source,
        ))
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
        use brokk_bifrost_analysis::analyzer::native_points::probe_jvm_assignment_value;

        use brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer;
        let analyzer = query.analyzer;

        Ok(Some(probe_jvm_assignment_value(
            resolve_analyzer::<crate::analyzer::JavaAnalyzer>(analyzer)
                .ok_or("assignment-value probe has no Java analyzer")?
                .inner(),
            query,
        )))
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
        let caller = resolve_analyzer::<JavaAnalyzer>(analyzer).ok_or_else(|| {
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

    fn build_model_provider(
        &self,
    ) -> Option<&'static dyn brokk_bifrost_analysis::analyzer::topology::BuildModelProvider> {
        Some(&crate::analyzer::jvm::topology::JVM_BUILD_MODEL)
    }

    fn workspace_external_member_family(
        &self,
        workspace: &brokk_bifrost_analysis::analyzer::multi_analyzer::MultiAnalyzer,
        identity: &brokk_bifrost_jvm::realm::JvmExternalMemberIdentity,
        max_visits: usize,
        cancellation: Option<&brokk_bifrost_core::cancellation::CancellationToken>,
    ) -> brokk_bifrost_analysis::analyzer::usages::member_family::ExternalMemberFamilyAnswer {
        if let Some(language) = [Language::Kotlin, Language::Scala]
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
        let Some(java) = brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer::<
            JavaAnalyzer,
        >(workspace) else {
            return brokk_bifrost_analysis::analyzer::usages::member_family::ExternalMemberFamilyAnswer::unsupported();
        };
        java.resolve_external_member_family(workspace, identity, max_visits, cancellation)
    }

    fn workspace_semantic_diagnostics(
        &self,
        workspace: &brokk_bifrost_analysis::analyzer::multi_analyzer::MultiAnalyzer,
        token: brokk_bifrost_core::analyzer::query_token::QueryToken<'_>,
        file: &ProjectFile,
        source: &str,
    ) -> Option<brokk_bifrost_core::analyzer::model::SemanticDiagnosticReport> {
        Some(diagnostics::collect_java_semantic_diagnostics(
            workspace, token, file, source,
        ))
    }

    fn knowledge(
        &self,
    ) -> &'static dyn brokk_bifrost_core::analyzer::language_knowledge::LanguageKnowledge {
        &brokk_bifrost_jvm::JavaKnowledge
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
                JavaAnalyzer::new_with_config_store_context(
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

    fn workspace_member_family_capability(
        &self,
        workspace: &brokk_bifrost_analysis::analyzer::multi_analyzer::MultiAnalyzer,
        member: &CodeUnit,
    ) -> brokk_bifrost_core::analyzer::structural::resolution::MemberFamilyCapability {
        brokk_bifrost_analysis::analyzer::usages::member_family::java_member_family_capability(
            workspace, member,
        )
    }

    fn workspace_member_family(
        &self,
        workspace: &brokk_bifrost_analysis::analyzer::multi_analyzer::MultiAnalyzer,
        member: &CodeUnit,
        cancellation: Option<&brokk_bifrost_core::cancellation::CancellationToken>,
    ) -> brokk_bifrost_analysis::analyzer::usages::member_family::MemberFamilyAnswer {
        brokk_bifrost_analysis::analyzer::usages::member_family::java_member_family(
            workspace,
            workspace,
            member,
            cancellation,
        )
    }

    fn native_member_attribution(
        &self,
        context: &brokk_bifrost_analysis::analyzer::store::resolution_operation::native_units::ProjectedNativeMemberContext,
        _outcome: brokk_bifrost_core::analyzer::structural::resolution::CandidateOutcome,
    ) -> Option<brokk_bifrost_analysis::analyzer::languages::NativeMemberAttribution> {
        Some(crate::analyzer::jvm::native_member_attribution(context))
    }

    fn native_non_reference_site(&self, node: tree_sitter::Node<'_>) -> bool {
        node.parent().is_some_and(|parent| {
            parent.child_by_field_name("name") == Some(node)
                && (brokk_bifrost_jvm::java::declarations::is_declaration_parent(parent.kind())
                    || matches!(
                        parent.kind(),
                        "constructor_declaration"
                            | "compact_constructor_declaration"
                            | "annotation_type_declaration"
                            | "annotation_type_element_declaration"
                            | "enum_constant"
                            | "type_parameter"
                    ))
        })
    }

    fn external_inventory_providers(
        &self,
        analyzer: &dyn brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer,
    ) -> Vec<String> {
        crate::analyzer::jvm::external::java_inventory_providers(analyzer)
    }

    #[cfg(any(test, feature = "test-support"))]
    fn native_rollout_points(
        &self,
    ) -> Option<&'static dyn brokk_bifrost_analysis::analyzer::languages::StructuralReceiverResolver>
    {
        Some(&crate::analyzer::jvm::native_points::JVM_NATIVE_ROLLOUT_POINTS)
    }

    fn explicit_import_model_target(
        &self,
        analyzer: &dyn brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer,
        token: brokk_bifrost_core::analyzer::query_token::QueryToken<'_>,
        file: &brokk_bifrost_core::analyzer::model::ProjectFile,
        reference: &brokk_bifrost_core::analyzer::usages::reference_site::ResolvedReferenceSite,
    ) -> Option<String> {
        crate::analyzer::jvm::import_routes::explicit_import_model_route(
            analyzer, token, file, reference,
        )
        .map(|route| route.target)
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

    fn lexical_pattern_bindings(
        &self,
    ) -> Option<brokk_bifrost_analysis::analyzer::languages::LexicalPatternBindings> {
        use brokk_bifrost_jvm::java::structural::{
            java_pattern_binding_declaration, java_pattern_binding_visible,
            java_pattern_bindings_may_escape_scope, java_pattern_scope,
        };
        Some(
            brokk_bifrost_analysis::analyzer::languages::LexicalPatternBindings {
                declaration_for_name: java_pattern_binding_declaration,
                is_scope: java_pattern_scope,
                visible_at: java_pattern_binding_visible,
                bindings_may_escape_scope: java_pattern_bindings_may_escape_scope,
            },
        )
    }

    fn pattern_binding_name_provider(&self) -> Option<PatternBindingNameProvider> {
        Some(brokk_bifrost_jvm::java::structural::java_pattern_binding_name)
    }

    fn call_argument_conversion_prover(
        &self,
    ) -> Option<&'static dyn brokk_bifrost_analysis::analyzer::usages::call_conversion::CallArgumentConversionProver>
{
        Some(&call_conversion::CALL_ARGUMENT_CONVERSION_PROVER)
    }

    fn expand_imported_external_callee(
        &self,
        analyzer: &dyn IAnalyzer,
        file: &ProjectFile,
        callee_text: &str,
        site: Option<&brokk_bifrost_analysis::analyzer::languages::ExternalCalleeSite<'_>>,
    ) -> Option<brokk_bifrost_analysis::analyzer::languages::ImportedExternalCallee> {
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
            (parent.kind() == "method_invocation"
                && parent.child_by_field_name("name") == Some(focus))
                || (parent.kind() == "field_access"
                    && parent.child_by_field_name("field") == Some(focus))
        })
    }

    fn declaration_ranges_limited(
        &self,
        analyzer: &dyn IAnalyzer,
        unit: &CodeUnit,
        limit: usize,
    ) -> Option<LimitedQueryRows<Range>> {
        brokk_bifrost_analysis::analyzer::languages::with_resolved_analyzer::<JavaAnalyzer, _>(
            analyzer,
            |java| java.inner().ranges_limited(unit, limit),
        )
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
        brokk_bifrost_analysis::analyzer::multi_analyzer::forward_query_provider::<JavaAnalyzer>(
            analyzer,
        )
    }

    fn ecosystem(&self) -> UsageEcosystem {
        UsageEcosystem::Jvm
    }

    fn dependency_pack_resolver(
        &self,
    ) -> Option<&'static dyn brokk_bifrost_analysis::analyzer::semantic_model::dependency::DependencyResolver>{
        Some(&crate::analyzer::jvm::dependency_packs::JvmDependencyResolver)
    }

    fn is_file_dependency_input(&self, path: &std::path::Path) -> bool {
        crate::analyzer::jvm::dependency_discovery::is_jvm_dependency_input_path(path)
    }

    fn configure_dependency_workspace(
        &self,
        config: &mut brokk_bifrost_core::analyzer::config::AnalyzerConfig,
        project_root: &std::path::Path,
    ) -> Result<(), brokk_bifrost_analysis::analyzer::store::StoreError> {
        crate::analyzer::jvm::dependency_packs::configure_dependency_workspace(config, project_root)
    }

    fn dependency_source_artifacts(
        &self,
        config: &brokk_bifrost_core::analyzer::config::AnalyzerConfig,
        project_root: &std::path::Path,
        outcomes: &[brokk_bifrost_analysis::analyzer::workspace::DependencyPackEcosystemOutcome],
    ) -> Option<
        brokk_bifrost_core::hash::HashMap<
            std::path::PathBuf,
            brokk_bifrost_analysis::analyzer::semantic_model::SemanticModelActivationEvidence,
        >,
    > {
        crate::analyzer::jvm::dependency_packs::prepared_jdk_artifacts_for_source_bindings(
            config,
            project_root,
            outcomes,
        )
    }

    fn reference_usage_strategy(
        &self,
    ) -> &'static dyn brokk_bifrost_analysis::analyzer::usages::traits::GraphUsageAnalyzer {
        &JAVA_USAGE_STRATEGY
    }

    fn bounded_type_resolution(
        &self,
        definitions: &brokk_bifrost_analysis::analyzer::analyzer_definition_lookup::AnalyzerDefinitionLookup<'_>,
        language: Language,
        query: brokk_bifrost_analysis::analyzer::languages::BoundedReceiverQuery<'_>,
    ) -> Option<
        brokk_bifrost_core::analyzer::usages::resolution_session::BoundedResolution<
            brokk_bifrost_analysis::analyzer::usages::get_type::TypeLookupOutcome,
        >,
    > {
        definitions.set_language(language);
        let session = crate::analyzer::usages::get_definition::java::JavaResolutionSession::bounded(
            definitions,
            query.budget,
            None,
        );
        Some(
            crate::analyzer::usages::get_type::java::resolve_java_type_bounded(
                query.analyzer,
                &session,
                query.file,
                query.source,
                query.tree,
                query.site,
            ),
        )
    }

    fn reference_graph_backend(
        &self,
    ) -> brokk_bifrost_analysis::analyzer::languages::LanguageGraphBackend {
        if super::jvm::native_graph::native_jvm_graph_selected() {
            brokk_bifrost_analysis::analyzer::languages::LanguageGraphBackend::Native(
                &super::jvm::native_graph::JVM_NATIVE_GRAPH,
            )
        } else {
            brokk_bifrost_analysis::analyzer::languages::LanguageGraphBackend::Legacy(&JavaEdgePass)
        }
    }

    #[cfg(any(test, feature = "test-support"))]
    fn trial_definition(
        &self,
        query: brokk_bifrost_analysis::analyzer::languages::BoundedReceiverQuery<'_>,
    ) -> Option<brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionResolution>
    {
        crate::analyzer::usages::get_definition::java::trial_definition(query)
    }

    #[cfg(any(test, feature = "test-support"))]
    fn native_point_batch(
        &self,
        analyzer: &dyn brokk_bifrost_analysis::analyzer::IAnalyzer,
        file: brokk_bifrost_core::analyzer::model::ProjectFile,
        source: std::sync::Arc<str>,
        cancellation: Option<&brokk_bifrost_core::cancellation::CancellationToken>,
    ) -> Option<brokk_bifrost_analysis::analyzer::native_points::NativePointBatch> {
        std::env::var_os("BIFROST_TRIAL_NATIVE_JAVA")?;
        let java = brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer::<
            JavaAnalyzer,
        >(analyzer)?;
        match brokk_bifrost_analysis::analyzer::native_points::NativePointBatch::new(
            &java.inner,
            analyzer,
            file,
            source,
            cancellation,
        ) {
            Ok(batch) => batch,
            Err(error) => {
                analyzer.mark_execution_dependent();
                brokk_bifrost_core::profiling::note_with(|| {
                    format!("native_point.memo batch unavailable: {error}")
                });
                None
            }
        }
    }

    #[cfg(any(test, feature = "test-support"))]
    fn trial_definition_in_batch(
        &self,
        query: brokk_bifrost_analysis::analyzer::languages::BoundedReceiverQuery<'_>,
        batch: Option<&brokk_bifrost_analysis::analyzer::native_points::NativePointBatch>,
    ) -> Option<brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionResolution>
    {
        crate::analyzer::usages::get_definition::java::trial_definition_in_batch(query, batch)
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
        crate::analyzer::usages::get_definition::java::resolve_definition_dispatch(
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
        crate::analyzer::usages::get_definition::java::java_call_reference_candidate(node)
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
        use crate::analyzer::JavaAnalyzer;

        use brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer;
        resolve_analyzer::<JavaAnalyzer>(analyzer).map(|java| {
            java.external_boundary_evidence(token, analyzer.semantic_model_overlay(), file, name)
        })
    }

    fn dead_code(&self) -> DeadCodeSupport {
        DeadCodeSupport {
            strategy: Some(&JAVA_USAGE_STRATEGY),
            bulk: Some(&JavaDeadCodeBulk),
        }
    }
}
impl brokk_bifrost_analysis::analyzer::store::StoreLanguageSupport for JavaSupport {
    fn precedence_rules(
        &self,
    ) -> &'static dyn brokk_bifrost_analysis::analyzer::resolution::precedence::PrecedenceRules
    {
        use brokk_bifrost_analysis::analyzer::resolution::precedence;
        precedence::JAVA_PRECEDENCE_RULES
    }

    fn supports_direct_type_shapes(&self) -> bool {
        true
    }

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
        Some(&call_applicability::JAVA_CALL_APPLICABILITY_ADAPTER)
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
        build_fqn_bulk_edges(
            analyzer,
            Language::Java,
            candidates,
            |analyzer, nodes, _kinds| build_java_usage_edges(analyzer, nodes, |_| true),
        )
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
impl brokk_bifrost_analysis::analyzer::usages::member_family::MemberFamilyProvider
    for JavaAnalyzer
{
    fn member_family_capability(
        &self,
        member: &CodeUnit,
    ) -> brokk_bifrost_core::analyzer::structural::resolution::MemberFamilyCapability {
        brokk_bifrost_analysis::analyzer::usages::member_family::java_member_family_capability(
            self, member,
        )
    }

    fn member_family(
        &self,
        member: &CodeUnit,
        cancellation: Option<&brokk_bifrost_core::cancellation::CancellationToken>,
    ) -> brokk_bifrost_analysis::analyzer::usages::member_family::MemberFamilyAnswer {
        brokk_bifrost_analysis::analyzer::usages::member_family::java_member_family(
            self,
            self,
            member,
            cancellation,
        )
    }

    fn external_member_family(
        &self,
        identity: &brokk_bifrost_jvm::realm::JvmExternalMemberIdentity,
        max_visits: usize,
        cancellation: Option<&brokk_bifrost_core::cancellation::CancellationToken>,
    ) -> brokk_bifrost_analysis::analyzer::usages::member_family::ExternalMemberFamilyAnswer {
        self.resolve_external_member_family(self, identity, max_visits, cancellation)
    }
}

mod receiver_query;
