use crate::analyzer::common::{language_for_file, workspace_language_for_file};
use crate::analyzer::jvm::realm_builder::jvm_source_realm;
use crate::analyzer::store::StoreError;
use crate::analyzer::{
    AdditionalFileDependencies, AnalyzerConfig, AnalyzerStoreContext, BuildProgress,
    CSharpAnalyzer, CloneSmell, CloneSmellWeights, CodeUnit, CommentDensityStats, CppAnalyzer,
    DeclarationInfo, DefinitionLanguageScope, ExceptionHandlingAnalysis, ExceptionSmellWeights,
    FileDependencyFacts, ForwardQueryProvider, GoAnalyzer, IAnalyzer, ImportAnalysisProvider,
    ImportInfo, ImportReachability, JavaAnalyzer, JavascriptAnalyzer, KotlinAnalyzer, Language,
    PhpAnalyzer, Project, ProjectFile, PythonAnalyzer, QueryReadIncomplete, Range,
    RelationalBatchError, RelationalBatchOutcome, RelationalDefinitionRequest,
    RelationalDefinitionResult, RelationalDefinitionValue, RubyAnalyzer, RustAnalyzer,
    ScalaAnalyzer, SearchSymbolCandidates, SearchSymbolPatternBatch, SignatureMetadata,
    SummaryFileProjection, TestAssertionAnalysis, TestAssertionSmell, TestAssertionWeights,
    TestDetectionProvider, TypeAliasProvider, TypeHierarchyProvider, TypescriptAnalyzer,
};
use crate::analyzer::{AnalyzerQueryScope, QueryScope};
use crate::hash::{HashMap, HashSet};
use crate::profiling;
use brokk_bifrost_core::analyzer::query_token::QueryToken;
use brokk_bifrost_jvm::realm::JvmSourceRealm;
use rayon::prelude::*;
use std::any::Any;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

/// Resolve a concrete analyzer of type `T` out of a `&dyn IAnalyzer`, whether it is
/// that analyzer directly or a [`MultiAnalyzer`] holding it as a per-language delegate.
///
/// The contract: `T` must be a concrete analyzer type (`RustAnalyzer`,
/// `CppAnalyzer`, ...); `None` means the workspace holds no analyzer of that
/// type, which callers treat as "no declarations of that language exist" --
/// never as an error. This is the one supported downcast from the framework's
/// `&dyn IAnalyzer` into a language analyzer; host crates (e.g. the LSP
/// handlers) call it rather than re-deriving the delegate walk.
pub fn resolve_analyzer<T: Any>(analyzer: &dyn IAnalyzer) -> Option<&T> {
    if let Some(direct) = (analyzer as &dyn Any).downcast_ref::<T>() {
        return Some(direct);
    }
    let multi = (analyzer as &dyn Any).downcast_ref::<MultiAnalyzer>()?;
    multi
        .delegates()
        .values()
        .find_map(|delegate| (delegate.analyzer() as &dyn Any).downcast_ref::<T>())
}

pub(crate) fn forward_query_provider<T: Any + ForwardQueryProvider>(
    analyzer: &dyn IAnalyzer,
) -> Option<&dyn ForwardQueryProvider> {
    resolve_analyzer::<T>(analyzer).map(|value| value as _)
}

// One delegate exists per language in a workspace, so the variants' size
// difference (the analyzers' per-file memo caches) costs nothing worth a Box.
#[allow(clippy::large_enum_variant)]
#[derive(Clone)]
pub enum AnalyzerDelegate {
    Java(JavaAnalyzer),
    CSharp(CSharpAnalyzer),
    Cpp(CppAnalyzer),
    Go(GoAnalyzer),
    JavaScript(JavascriptAnalyzer),
    Php(PhpAnalyzer),
    Python(PythonAnalyzer),
    TypeScript(TypescriptAnalyzer),
    Rust(RustAnalyzer),
    Scala(ScalaAnalyzer),
    Ruby(RubyAnalyzer),
    Kotlin(KotlinAnalyzer),
}

impl AnalyzerDelegate {
    pub(crate) fn analyzer(&self) -> &dyn IAnalyzer {
        match self {
            Self::Java(analyzer) => analyzer,
            Self::CSharp(analyzer) => analyzer,
            Self::Cpp(analyzer) => analyzer,
            Self::Go(analyzer) => analyzer,
            Self::JavaScript(analyzer) => analyzer,
            Self::Php(analyzer) => analyzer,
            Self::Python(analyzer) => analyzer,
            Self::TypeScript(analyzer) => analyzer,
            Self::Rust(analyzer) => analyzer,
            Self::Scala(analyzer) => analyzer,
            Self::Ruby(analyzer) => analyzer,
            Self::Kotlin(analyzer) => analyzer,
        }
    }

    pub(crate) fn program_semantics_provider(
        &self,
    ) -> &dyn crate::analyzer::semantic::ProgramSemanticsProvider {
        match self {
            Self::Java(analyzer) => analyzer,
            Self::CSharp(analyzer) => analyzer,
            Self::Cpp(analyzer) => analyzer,
            Self::Go(analyzer) => analyzer,
            Self::JavaScript(analyzer) => analyzer,
            Self::Php(analyzer) => analyzer,
            Self::Python(analyzer) => analyzer,
            Self::TypeScript(analyzer) => analyzer,
            Self::Rust(analyzer) => analyzer,
            Self::Scala(analyzer) => analyzer,
            Self::Ruby(analyzer) => analyzer,
            Self::Kotlin(analyzer) => analyzer,
        }
    }

    pub(crate) fn clone_with_project(&self, project: Arc<dyn Project>) -> Self {
        match self {
            Self::Java(analyzer) => Self::Java(analyzer.clone_with_project(project)),
            Self::CSharp(analyzer) => Self::CSharp(analyzer.clone_with_project(project)),
            Self::Cpp(analyzer) => Self::Cpp(analyzer.clone_with_project(project)),
            Self::Go(analyzer) => Self::Go(analyzer.clone_with_project(project)),
            Self::JavaScript(analyzer) => Self::JavaScript(analyzer.clone_with_project(project)),
            Self::Php(analyzer) => Self::Php(analyzer.clone_with_project(project)),
            Self::Python(analyzer) => Self::Python(analyzer.clone_with_project(project)),
            Self::TypeScript(analyzer) => Self::TypeScript(analyzer.clone_with_project(project)),
            Self::Rust(analyzer) => Self::Rust(analyzer.clone_with_project(project)),
            Self::Scala(analyzer) => Self::Scala(analyzer.clone_with_project(project)),
            Self::Ruby(analyzer) => Self::Ruby(analyzer.clone_with_project(project)),
            Self::Kotlin(analyzer) => Self::Kotlin(analyzer.clone_with_project(project)),
        }
    }

    pub(crate) fn clone_for_index_warm(&self, project: Arc<dyn Project>) -> Self {
        match self {
            Self::Java(analyzer) => Self::Java(analyzer.clone_for_index_warm(project)),
            Self::CSharp(analyzer) => Self::CSharp(analyzer.clone_for_index_warm(project)),
            Self::Cpp(analyzer) => Self::Cpp(analyzer.clone_with_project(project)),
            Self::Go(analyzer) => Self::Go(analyzer.clone_with_project(project)),
            Self::JavaScript(analyzer) => Self::JavaScript(analyzer.clone_with_project(project)),
            Self::Php(analyzer) => Self::Php(analyzer.clone_with_project(project)),
            Self::Python(analyzer) => Self::Python(analyzer.clone_with_project(project)),
            Self::TypeScript(analyzer) => Self::TypeScript(analyzer.clone_with_project(project)),
            Self::Rust(analyzer) => Self::Rust(analyzer.clone_for_index_warm(project)),
            Self::Scala(analyzer) => Self::Scala(analyzer.clone_for_index_warm(project)),
            Self::Ruby(analyzer) => Self::Ruby(analyzer.clone_with_project(project)),
            Self::Kotlin(analyzer) => Self::Kotlin(analyzer.clone_for_index_warm(project)),
        }
    }

    fn import_analysis_provider(&self) -> Option<&dyn ImportAnalysisProvider> {
        match self {
            Self::Java(analyzer) => Some(analyzer),
            Self::CSharp(analyzer) => Some(analyzer),
            Self::Cpp(analyzer) => Some(analyzer),
            Self::Go(analyzer) => Some(analyzer),
            Self::JavaScript(analyzer) => Some(analyzer),
            Self::Php(analyzer) => analyzer.import_analysis_provider(),
            Self::Python(analyzer) => Some(analyzer),
            Self::TypeScript(analyzer) => Some(analyzer),
            Self::Rust(analyzer) => Some(analyzer),
            Self::Scala(analyzer) => analyzer.import_analysis_provider(),
            Self::Ruby(analyzer) => Some(analyzer),
            Self::Kotlin(analyzer) => Some(analyzer),
        }
    }

    fn type_hierarchy_provider(&self) -> Option<&dyn TypeHierarchyProvider> {
        match self {
            Self::Java(analyzer) => Some(analyzer),
            Self::CSharp(analyzer) => analyzer.type_hierarchy_provider(),
            Self::Cpp(analyzer) => analyzer.type_hierarchy_provider(),
            Self::Go(analyzer) => analyzer.type_hierarchy_provider(),
            Self::JavaScript(analyzer) => analyzer.type_hierarchy_provider(),
            Self::Php(analyzer) => analyzer.type_hierarchy_provider(),
            Self::Python(analyzer) => Some(analyzer),
            Self::TypeScript(analyzer) => analyzer.type_hierarchy_provider(),
            Self::Rust(analyzer) => analyzer.type_hierarchy_provider(),
            Self::Scala(analyzer) => analyzer.type_hierarchy_provider(),
            Self::Ruby(analyzer) => Some(analyzer),
            Self::Kotlin(analyzer) => analyzer.type_hierarchy_provider(),
        }
    }

    fn type_alias_provider(&self) -> Option<&dyn TypeAliasProvider> {
        match self {
            Self::Java(analyzer) => analyzer.type_alias_provider(),
            Self::CSharp(analyzer) => analyzer.type_alias_provider(),
            Self::Cpp(analyzer) => analyzer.type_alias_provider(),
            Self::Go(analyzer) => analyzer.type_alias_provider(),
            Self::JavaScript(analyzer) => analyzer.type_alias_provider(),
            Self::Php(analyzer) => analyzer.type_alias_provider(),
            Self::Python(analyzer) => analyzer.type_alias_provider(),
            Self::TypeScript(analyzer) => analyzer.type_alias_provider(),
            Self::Rust(analyzer) => analyzer.type_alias_provider(),
            Self::Scala(analyzer) => analyzer.type_alias_provider(),
            Self::Ruby(analyzer) => analyzer.type_alias_provider(),
            Self::Kotlin(analyzer) => analyzer.type_alias_provider(),
        }
    }

    fn test_detection_provider(&self) -> Option<&dyn TestDetectionProvider> {
        match self {
            Self::Java(analyzer) => Some(analyzer),
            Self::CSharp(analyzer) => Some(analyzer),
            Self::Cpp(analyzer) => analyzer.test_detection_provider(),
            Self::Go(analyzer) => Some(analyzer),
            Self::JavaScript(analyzer) => Some(analyzer),
            Self::Php(analyzer) => Some(analyzer),
            Self::Python(analyzer) => Some(analyzer),
            Self::TypeScript(analyzer) => Some(analyzer),
            Self::Rust(analyzer) => Some(analyzer),
            Self::Scala(analyzer) => Some(analyzer),
            Self::Ruby(analyzer) => Some(analyzer),
            Self::Kotlin(analyzer) => Some(analyzer),
        }
    }

    pub(crate) fn update(&self, changed_files: &BTreeSet<ProjectFile>) -> Self {
        match self {
            Self::Java(analyzer) => Self::Java(analyzer.update(changed_files)),
            Self::CSharp(analyzer) => Self::CSharp(analyzer.update(changed_files)),
            Self::Cpp(analyzer) => Self::Cpp(analyzer.update(changed_files)),
            Self::Go(analyzer) => Self::Go(analyzer.update(changed_files)),
            Self::JavaScript(analyzer) => Self::JavaScript(analyzer.update(changed_files)),
            Self::Php(analyzer) => Self::Php(analyzer.update(changed_files)),
            Self::Python(analyzer) => Self::Python(analyzer.update(changed_files)),
            Self::TypeScript(analyzer) => Self::TypeScript(analyzer.update(changed_files)),
            Self::Rust(analyzer) => Self::Rust(analyzer.update(changed_files)),
            Self::Scala(analyzer) => Self::Scala(analyzer.update(changed_files)),
            Self::Ruby(analyzer) => Self::Ruby(analyzer.update(changed_files)),
            Self::Kotlin(analyzer) => Self::Kotlin(analyzer.update(changed_files)),
        }
    }

    fn should_receive_changed_file(&self, language: Language, file: &ProjectFile) -> bool {
        language_for_file(file) == language
            || self.analyzer().is_analyzed(file)
            || is_language_configuration_input(language, file)
    }

    pub(crate) fn update_all_with_progress(&self, progress: Option<BuildProgress>) -> Self {
        match self {
            Self::Java(analyzer) => Self::Java(analyzer.update_all_with_progress(progress)),
            Self::CSharp(analyzer) => Self::CSharp(analyzer.update_all_with_progress(progress)),
            Self::Cpp(analyzer) => Self::Cpp(analyzer.update_all_with_progress(progress)),
            Self::Go(analyzer) => Self::Go(analyzer.update_all_with_progress(progress)),
            Self::JavaScript(analyzer) => {
                Self::JavaScript(analyzer.update_all_with_progress(progress))
            }
            Self::Php(analyzer) => Self::Php(analyzer.update_all_with_progress(progress)),
            Self::Python(analyzer) => Self::Python(analyzer.update_all_with_progress(progress)),
            Self::TypeScript(analyzer) => {
                Self::TypeScript(analyzer.update_all_with_progress(progress))
            }
            Self::Rust(analyzer) => Self::Rust(analyzer.update_all_with_progress(progress)),
            Self::Scala(analyzer) => Self::Scala(analyzer.update_all_with_progress(progress)),
            Self::Ruby(analyzer) => Self::Ruby(analyzer.update_all_with_progress(progress)),
            Self::Kotlin(analyzer) => Self::Kotlin(analyzer.update_all_with_progress(progress)),
        }
    }
}

/// Construct the concrete analyzer serving `language`.
///
/// Assembly-layer code: this is the one place outside the registry allowed to name
/// concrete per-language analyzer types, because concrete storage and construction is
/// what [`AnalyzerDelegate`] is for.
pub(crate) fn build_language_delegate(
    language: Language,
    project: Arc<dyn Project>,
    config: AnalyzerConfig,
    mut store_context: AnalyzerStoreContext,
    progress: Option<BuildProgress>,
) -> Result<AnalyzerDelegate, StoreError> {
    let _scope = profiling::scope(format!("WorkspaceAnalyzer::build[{language:?}]"));
    // Each delegate owns its language-specific live-path generation while all
    // delegates share the store and generation identities.
    store_context.live_paths =
        Arc::new(crate::analyzer::store::liveness::LivePathMap::trust_filesystem_generation());
    macro_rules! build_delegate {
        ($variant:ident, $analyzer:ty) => {
            AnalyzerDelegate::$variant(<$analyzer>::new_with_config_store_context(
                project,
                config,
                store_context,
                progress,
            )?)
        };
    }
    Ok(match language {
        Language::Java => build_delegate!(Java, JavaAnalyzer),
        Language::Go => build_delegate!(Go, GoAnalyzer),
        Language::Cpp => build_delegate!(Cpp, CppAnalyzer),
        Language::JavaScript => build_delegate!(JavaScript, JavascriptAnalyzer),
        Language::TypeScript => build_delegate!(TypeScript, TypescriptAnalyzer),
        Language::Python => build_delegate!(Python, PythonAnalyzer),
        Language::Rust => build_delegate!(Rust, RustAnalyzer),
        Language::Php => build_delegate!(Php, PhpAnalyzer),
        Language::Scala => build_delegate!(Scala, ScalaAnalyzer),
        Language::CSharp => build_delegate!(CSharp, CSharpAnalyzer),
        Language::Ruby => build_delegate!(Ruby, RubyAnalyzer),
        Language::Kotlin => build_delegate!(Kotlin, KotlinAnalyzer),
        Language::None => unreachable!("Language::None is filtered before delegate build"),
    })
}

/// Construction state retained by a workspace so an incremental update can
/// add a delegate for a language that was not present at startup.
///
/// A delegate owns a language-specific fork of `store_context.live_paths`, but
/// all delegates created for one workspace must continue to share the same
/// store, GC coordinator, liveness source, and analyzer configuration. Keeping
/// that state here avoids silently rebuilding a newly discovered language with
/// default configuration or an unrelated in-memory store. The initial build's
/// progress callback is deliberately absent: it belongs to that one build and
/// must neither be retained nor receive later incremental-work notifications.
#[derive(Clone)]
pub(crate) struct WorkspaceBuildContext {
    project: Arc<dyn Project>,
    config: AnalyzerConfig,
    store_context: AnalyzerStoreContext,
    #[cfg(test)]
    startup_oid_batches: Option<Arc<AtomicUsize>>,
    requested_languages: Option<BTreeSet<Language>>,
}

impl WorkspaceBuildContext {
    pub(crate) fn new(
        project: Arc<dyn Project>,
        config: AnalyzerConfig,
        store_context: AnalyzerStoreContext,
        requested_languages: Option<BTreeSet<Language>>,
    ) -> Self {
        Self {
            project,
            config,
            store_context,
            #[cfg(test)]
            startup_oid_batches: None,
            requested_languages: requested_languages.filter(|languages| !languages.is_empty()),
        }
    }

    pub(crate) fn clone_with_project(&self, project: Arc<dyn Project>) -> Self {
        let mut context = self.clone();
        context.project = project;
        context
    }

    pub(crate) fn project(&self) -> &Arc<dyn Project> {
        &self.project
    }

    /// The configuration this workspace was built from, which is where
    /// behavior a host selects (rather than a per-query budget) lives.
    pub(crate) fn config(&self) -> &AnalyzerConfig {
        &self.config
    }

    /// The store context every delegate of this workspace was built against.
    pub(crate) fn store_context(&self) -> &AnalyzerStoreContext {
        &self.store_context
    }

    /// The languages this workspace was restricted to, or `None` for every
    /// language the project holds.
    pub(crate) fn requested_languages(&self) -> Option<&BTreeSet<Language>> {
        self.requested_languages.as_ref()
    }

    pub(crate) fn derived_layer_budget_bytes(&self) -> u64 {
        self.config.memo_cache_budget_bytes() / 8
    }

    /// The on-disk path of the analyzer store this workspace was built
    /// against, or `None` when the store lives only in memory.
    pub(crate) fn store_db_path(&self) -> Option<&std::path::Path> {
        self.store_context.store.db_path()
    }

    /// The analyzer store this workspace reads from and publishes to.
    ///
    /// Everything a workspace derives is keyed by content, so a caller that
    /// derives something of its own -- a policy evaluation unit -- publishes
    /// it into the same store rather than opening a second one that would have
    /// to be kept in step with this one.
    pub(crate) fn store(&self) -> &Arc<crate::analyzer::store::AnalyzerStore> {
        &self.store_context.store
    }

    fn read_import_graph(
        &self,
        content_identity: crate::analyzer::content_identity::WorkspaceContentIdentity,
        direction: crate::analyzer::PersistedImportDirection,
        files: &[ProjectFile],
        edge_limit: usize,
    ) -> crate::analyzer::store::Result<Option<crate::analyzer::PersistedImportAdjacency>> {
        let paths = files
            .iter()
            .map(crate::path_utils::rel_path_string)
            .collect::<Vec<_>>();
        let store_direction = match direction {
            crate::analyzer::PersistedImportDirection::Forward => {
                crate::analyzer::store::WorkspaceImportDirection::Forward
            }
            crate::analyzer::PersistedImportDirection::Reverse => {
                crate::analyzer::store::WorkspaceImportDirection::Reverse
            }
        };
        let Some(read) = self.store_context.store.read_workspace_import_graph(
            &self.store_context.workspace_id,
            content_identity.as_bytes(),
            store_direction,
            &paths,
            edge_limit,
        )?
        else {
            return Ok(None);
        };
        let mut by_file = files
            .iter()
            .cloned()
            .map(|file| (file, Vec::new()))
            .collect::<crate::hash::HashMap<_, _>>();
        let root_file = files.first();
        for (importer, target) in &read.edges {
            let (seed_path, adjacency_path) = match direction {
                crate::analyzer::PersistedImportDirection::Forward => (importer, target),
                crate::analyzer::PersistedImportDirection::Reverse => (target, importer),
            };
            let root_file = root_file.expect("stored adjacency rows require source seeds");
            by_file
                .entry(root_file.with_rel_path(std::path::PathBuf::from(seed_path)))
                .or_insert_with(Vec::new)
                .push(root_file.with_rel_path(std::path::PathBuf::from(adjacency_path)));
        }
        for adjacency in by_file.values_mut() {
            adjacency.sort();
            adjacency.dedup();
        }
        Ok(Some(crate::analyzer::PersistedImportAdjacency {
            rows_read: read.edges.len(),
            by_file,
            exhausted: read.exhausted,
        }))
    }

    fn import_graph_resolver_identity(
        &self,
        languages: &[String],
    ) -> crate::analyzer::store::Result<[u8; 32]> {
        self.store_context
            .store
            .workspace_import_resolver_identity(format!("{:?}", self.config), languages)
    }

    fn plan_import_graph_refresh(
        &self,
        content_identity: crate::analyzer::content_identity::WorkspaceContentIdentity,
        resolver_identity: &[u8; 32],
        sources: &[crate::analyzer::store::WorkspaceImportGraphSource],
    ) -> crate::analyzer::store::Result<crate::analyzer::store::WorkspaceImportGraphRefreshPlan>
    {
        self.store_context
            .store
            .plan_workspace_import_graph_refresh(
                &self.store_context.workspace_id,
                content_identity.as_bytes(),
                resolver_identity,
                sources,
            )
    }

    // Each value is an independent input to this one atomic publication.
    #[allow(clippy::too_many_arguments)]
    fn advance_import_graph_identity(
        &self,
        content_identity: crate::analyzer::content_identity::WorkspaceContentIdentity,
        resolver_identity: &[u8; 32],
        plan: &crate::analyzer::store::WorkspaceImportGraphRefreshPlan,
        sources: &[crate::analyzer::store::WorkspaceImportGraphSource],
    ) -> crate::analyzer::store::Result<bool> {
        self.store_context
            .store
            .advance_workspace_import_graph_identity(
                &self.store_context.workspace_id,
                content_identity.as_bytes(),
                resolver_identity,
                plan,
                sources,
            )
    }

    #[allow(clippy::too_many_arguments)]
    fn publish_import_graph_refresh(
        &self,
        content_identity: crate::analyzer::content_identity::WorkspaceContentIdentity,
        resolver_identity: &[u8; 32],
        plan: &crate::analyzer::store::WorkspaceImportGraphRefreshPlan,
        source_count: usize,
        sources: &[crate::analyzer::store::WorkspaceImportGraphSource],
        edges: &[crate::analyzer::PersistedImportEdge],
        dependencies: &[crate::analyzer::PersistedImportDependencies],
    ) -> crate::analyzer::store::Result<bool> {
        let edges = edges
            .iter()
            .map(|edge| crate::analyzer::store::WorkspaceImportGraphEdge {
                importer_path: crate::path_utils::rel_path_string(&edge.importer),
                import_ordinal: edge.import_ordinal,
                target_path: crate::path_utils::rel_path_string(&edge.target),
                provenance_json: edge.provenance_json.clone(),
                route_dependencies: edge.route_dependencies.clone(),
            })
            .collect::<Vec<_>>();
        let dependencies = dependencies
            .iter()
            .map(
                |dependency| crate::analyzer::store::WorkspaceImportGraphDependencies {
                    importer_path: crate::path_utils::rel_path_string(&dependency.importer),
                    lookups: dependency
                        .facts
                        .lookups
                        .iter()
                        .map(|lookup| {
                            (
                                lookup.import_ordinal,
                                crate::path_utils::rel_path_string(&lookup.consulted_file),
                                lookup.name.clone(),
                            )
                        })
                        .collect(),
                    missing_module_path_keys: dependency.facts.missing_module_path_keys.clone(),
                },
            )
            .collect::<Vec<_>>();
        self.store_context
            .store
            .publish_workspace_import_graph_refresh(
                &self.store_context.workspace_id,
                content_identity.as_bytes(),
                resolver_identity,
                plan,
                source_count,
                sources,
                &edges,
                &dependencies,
            )
    }

    #[cfg(test)]
    pub(crate) fn with_startup_oid_batch_counter_for_test(
        mut self,
        counter: Option<Arc<AtomicUsize>>,
    ) -> Self {
        self.startup_oid_batches = counter;
        self
    }

    #[cfg(test)]
    pub(crate) fn startup_oid_batch_count_for_test(&self) -> usize {
        self.startup_oid_batches
            .as_ref()
            .map_or(0, |count| count.load(Ordering::Relaxed))
    }

    fn allows_language(&self, language: Language) -> bool {
        language != Language::None
            && self
                .requested_languages
                .as_ref()
                .is_none_or(|languages| languages.contains(&language))
    }

    fn allowed_languages_for_files<'file>(
        &self,
        files: impl Iterator<Item = &'file ProjectFile>,
    ) -> BTreeSet<Language> {
        files
            .map(workspace_language_for_file)
            .filter(|language| self.allows_language(*language))
            .collect()
    }

    pub(crate) fn changed_languages(
        &self,
        changed_files: &BTreeSet<ProjectFile>,
    ) -> BTreeSet<Language> {
        self.allowed_languages_for_files(
            changed_files
                .iter()
                .filter(|file| file.exists() || self.project.has_overlay(file)),
        )
    }

    pub(crate) fn project_languages(&self) -> BTreeSet<Language> {
        let files = self
            .project
            .all_files_shared()
            .expect("failed to list workspace files while refreshing analyzer languages");
        self.allowed_languages_for_files(files.iter())
    }

    pub(crate) fn build_delegate(
        &self,
        language: Language,
    ) -> Result<AnalyzerDelegate, StoreError> {
        self.build_delegate_with_progress(language, None)
    }

    pub(crate) fn build_delegate_with_progress(
        &self,
        language: Language,
        progress: Option<BuildProgress>,
    ) -> Result<AnalyzerDelegate, StoreError> {
        debug_assert!(self.allows_language(language));
        build_language_delegate(
            language,
            Arc::clone(&self.project),
            self.config.clone(),
            self.store_context.clone(),
            progress,
        )
    }
}

/// Whether `file` is a configuration input of `language`'s analyzer: a file
/// that is not a source of that language but changes what its analyzer
/// publishes, such as `Cargo.toml` for Rust or `tsconfig.json` for
/// TypeScript. The workspace analyzer routes an edit to such a file to the
/// language's delegate, and the MCP file watcher watches every directory that
/// holds one, so both sides must agree on this one predicate.
pub fn is_language_configuration_input(language: Language, file: &ProjectFile) -> bool {
    match language {
        Language::Java | Language::Scala | Language::Kotlin => {
            crate::analyzer::jvm::dependency_discovery::is_jvm_dependency_input(file)
        }
        Language::CSharp => crate::analyzer::csharp::is_csharp_dependency_input(file),
        Language::Cpp => brokk_bifrost_cpp::compile_context::is_cpp_compile_context_input(file),
        Language::JavaScript | Language::TypeScript => is_js_ts_config_file(file),
        Language::Go => is_go_module_manifest(file),
        Language::Rust => crate::analyzer::rust::is_cargo_evidence_input(file),
        Language::Php | Language::Python | Language::Ruby | Language::None => false,
    }
}

fn is_js_ts_config_file(file: &ProjectFile) -> bool {
    matches!(
        file.rel_path().file_name().and_then(|name| name.to_str()),
        Some(
            "tsconfig.json"
                | "jsconfig.json"
                | "package.json"
                | "package-lock.json"
                | "npm-shrinkwrap.json"
                | "pnpm-lock.yaml"
                | "yarn.lock"
        )
    )
}

fn is_go_module_manifest(file: &ProjectFile) -> bool {
    matches!(
        file.rel_path().file_name().and_then(|name| name.to_str()),
        Some("go.mod" | "go.sum")
    )
}

fn group_files_by_language(
    files: &[ProjectFile],
    mut language_for: impl FnMut(&ProjectFile) -> Language,
) -> BTreeMap<Language, Vec<ProjectFile>> {
    let mut grouped: BTreeMap<Language, Vec<ProjectFile>> = BTreeMap::new();
    for file in files {
        grouped
            .entry(language_for(file))
            .or_default()
            .push(file.clone());
    }
    grouped
}

fn delegate_or_default<T>(
    delegate: Option<&AnalyzerDelegate>,
    query: impl FnOnce(&dyn IAnalyzer) -> T,
) -> T
where
    T: Default,
{
    delegate
        .map(|delegate| query(delegate.analyzer()))
        .unwrap_or_default()
}

pub struct MultiAnalyzer {
    delegates: BTreeMap<Language, AnalyzerDelegate>,
    build_context: Option<Arc<WorkspaceBuildContext>>,
    snapshot_caches: Arc<crate::analyzer::AnalyzerSnapshotCaches>,
    derived_layer_budget_bytes: u64,
    query_contexts: Mutex<Vec<Arc<crate::analyzer::AnalyzerQueryContext>>>,
    /// How many of the open query contexts carry a read ledger. Tracks
    /// `query_contexts`, which a clone starts empty, so it is minted fresh per
    /// clone rather than shared.
    attached_read_ledgers: AtomicUsize,
    /// One delegate's own file list is already sorted and single-language;
    /// `analyzed_files_for_language`'s override only has to look it up, but
    /// still re-sorted it on every call until this memoized it (bifrost#15).
    /// Shared like `snapshot_caches`: cloned by reference across a clone of
    /// the same snapshot, rebuilt fresh whenever the snapshot itself is.
    analyzed_files_by_language:
        Arc<brokk_bifrost_core::analyzer::pool_memo::KeyedPoolSafeMemo<Language, Vec<ProjectFile>>>,
    /// Calls to `resolve_definition_batch_with_source` recorded against this
    /// exact analyzer instance. That function receives whatever `&dyn
    /// IAnalyzer` its caller was given -- for a workspace, this `MultiAnalyzer`
    /// itself, not one of its per-language delegates -- so the count belongs
    /// here rather than being summed from `delegates` the way most other
    /// test-hook counters are. Kept per instance (not a process-wide static)
    /// so a batching test can read it from its own analyzer without another
    /// concurrently running test inflating the count (issue #3010).
    resolve_definition_batch_with_source_call_count: Arc<AtomicUsize>,
}

impl Default for MultiAnalyzer {
    fn default() -> Self {
        Self::new(BTreeMap::new())
    }
}

impl Clone for MultiAnalyzer {
    fn clone(&self) -> Self {
        Self {
            delegates: self.delegates.clone(),
            build_context: self.build_context.clone(),
            snapshot_caches: Arc::clone(&self.snapshot_caches),
            derived_layer_budget_bytes: self.derived_layer_budget_bytes,
            query_contexts: Mutex::new(Vec::new()),
            attached_read_ledgers: AtomicUsize::new(0),
            analyzed_files_by_language: Arc::clone(&self.analyzed_files_by_language),
            resolve_definition_batch_with_source_call_count: Arc::clone(
                &self.resolve_definition_batch_with_source_call_count,
            ),
        }
    }
}

impl MultiAnalyzer {
    pub(crate) fn update_all_with_progress(&self, progress: Option<BuildProgress>) -> Self {
        let mut delegates = self.delegates.clone();
        if let Some(context) = &self.build_context {
            let active_languages = context.project_languages();
            delegates.retain(|language, _| active_languages.contains(language));
            for language in active_languages {
                if let std::collections::btree_map::Entry::Vacant(entry) = delegates.entry(language)
                {
                    let delegate = context.build_delegate_with_progress(language, progress.clone()).unwrap_or_else(|error| {
                        panic!(
                            "failed to initialize {language:?} analyzer during full update: {error}"
                        )
                    });
                    entry.insert(delegate);
                }
            }
        }
        let delegates = delegates
            .iter()
            .collect::<Vec<_>>()
            .into_par_iter()
            .map(|(language, delegate)| {
                (
                    *language,
                    delegate.update_all_with_progress(progress.clone()),
                )
            })
            .collect();
        Self::new_with_build_context(
            delegates,
            self.derived_layer_budget_bytes,
            self.build_context.clone(),
        )
        .with_snapshot_caches(self.snapshot_caches.carry_content_keyed_values_forward())
    }

    fn prefetch_delegates(&self, fq_names: &[String]) {
        self.delegates
            .values()
            .for_each(|delegate| IAnalyzer::prefetch_definitions(delegate.analyzer(), fq_names));
    }

    #[cfg(any(test, feature = "test-support"))]
    fn delegate_test_hooks(
        &self,
    ) -> impl Iterator<Item = &dyn crate::analyzer::AnalyzerTestHooks> + '_ {
        self.delegates
            .values()
            .map(|delegate| delegate.analyzer().test_hooks())
    }

    #[cfg(any(test, feature = "test-support"))]
    fn sum_delegate_test_hook_counts(
        &self,
        count: impl Fn(&dyn crate::analyzer::AnalyzerTestHooks) -> usize,
    ) -> usize {
        self.delegate_test_hooks().map(count).sum()
    }

    pub fn new(delegates: BTreeMap<Language, AnalyzerDelegate>) -> Self {
        Self::new_with_derived_layer_budget(
            delegates,
            crate::analyzer::structural::derived_cache::SnapshotDerivedLayerCache::DEFAULT_MAX_RETAINED_BYTES,
        )
    }

    pub(crate) fn new_with_derived_layer_budget(
        delegates: BTreeMap<Language, AnalyzerDelegate>,
        derived_layer_budget_bytes: u64,
    ) -> Self {
        Self::new_with_build_context(delegates, derived_layer_budget_bytes, None)
    }

    pub(crate) fn new_for_workspace(
        delegates: BTreeMap<Language, AnalyzerDelegate>,
        build_context: Arc<WorkspaceBuildContext>,
    ) -> Self {
        let derived_layer_budget_bytes = build_context.derived_layer_budget_bytes();
        Self::new_with_build_context(delegates, derived_layer_budget_bytes, Some(build_context))
    }

    fn new_with_build_context(
        delegates: BTreeMap<Language, AnalyzerDelegate>,
        derived_layer_budget_bytes: u64,
        build_context: Option<Arc<WorkspaceBuildContext>>,
    ) -> Self {
        Self {
            delegates,
            build_context,
            snapshot_caches: Arc::new(crate::analyzer::AnalyzerSnapshotCaches::new(
                derived_layer_budget_bytes,
            )),
            derived_layer_budget_bytes,
            query_contexts: Mutex::new(Vec::new()),
            attached_read_ledgers: AtomicUsize::new(0),
            analyzed_files_by_language: Arc::new(
                brokk_bifrost_core::analyzer::pool_memo::KeyedPoolSafeMemo::new(),
            ),
            resolve_definition_batch_with_source_call_count: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Adopt the previous generation's content-keyed workspace caches (#2449).
    fn with_snapshot_caches(mut self, caches: crate::analyzer::AnalyzerSnapshotCaches) -> Self {
        self.snapshot_caches = Arc::new(caches);
        self
    }
    pub fn with_java(java: JavaAnalyzer) -> Self {
        Self::new(BTreeMap::from([(
            Language::Java,
            AnalyzerDelegate::Java(java),
        )]))
    }

    pub fn delegates(&self) -> &BTreeMap<Language, AnalyzerDelegate> {
        &self.delegates
    }

    pub(crate) fn workspace_build_context(&self) -> Option<Arc<WorkspaceBuildContext>> {
        self.build_context.clone()
    }

    pub(crate) fn build_context(&self) -> Option<&WorkspaceBuildContext> {
        self.build_context.as_deref()
    }

    pub(crate) fn clone_with_project(&self, project: Arc<dyn Project>) -> Self {
        Self {
            delegates: self
                .delegates
                .iter()
                .map(|(language, delegate)| {
                    (*language, delegate.clone_with_project(Arc::clone(&project)))
                })
                .collect(),
            build_context: self
                .build_context
                .as_ref()
                .map(|context| Arc::new(context.clone_with_project(project))),
            snapshot_caches: Arc::new(crate::analyzer::AnalyzerSnapshotCaches::new(
                self.derived_layer_budget_bytes,
            )),
            derived_layer_budget_bytes: self.derived_layer_budget_bytes,
            query_contexts: Mutex::new(Vec::new()),
            attached_read_ledgers: AtomicUsize::new(0),
            analyzed_files_by_language: Arc::new(
                brokk_bifrost_core::analyzer::pool_memo::KeyedPoolSafeMemo::new(),
            ),
            resolve_definition_batch_with_source_call_count: Arc::new(AtomicUsize::new(0)),
        }
    }

    pub(crate) fn clone_for_index_warm(&self, project: Arc<dyn Project>) -> Self {
        let mut clone = self.clone();
        clone.delegates = self
            .delegates
            .iter()
            .map(|(language, delegate)| {
                (
                    *language,
                    delegate.clone_for_index_warm(Arc::clone(&project)),
                )
            })
            .collect();
        clone.build_context = self
            .build_context
            .as_ref()
            .map(|context| Arc::new(context.clone_with_project(project)));
        clone
    }

    /// The delegate language a file's queries route to.
    ///
    /// The extension registry answers for every file it names. A file it does
    /// not name may still be analyzed, because a language claimed it through
    /// its own imports (#1837): route those to the one language that infers
    /// claims, so a query positioned inside an adopted `.inc` reaches the
    /// analyzer that indexed it instead of falling off the routing table.
    ///
    /// An unclaimed-extension file that inference did NOT adopt routes to that
    /// same delegate and finds nothing there, which is the same empty answer it
    /// got when it routed nowhere. Asking each delegate whether it analyzed the
    /// file would be exact, but that is a store round-trip on a path every
    /// query takes.
    ///
    /// CLAIMS SEAM: see [`crate::analyzer::languages::claim_inferring_languages`].
    /// With two inferring languages this must become a real lookup.
    fn dispatch_language(&self, file: &ProjectFile) -> Language {
        let language = language_for_file(file);
        if language != Language::None {
            return language;
        }
        crate::analyzer::languages::claim_inferring_languages()
            .iter()
            .copied()
            .find(|language| self.delegates.contains_key(language))
            .unwrap_or(Language::None)
    }

    pub(crate) fn delegate_for_file(&self, file: &ProjectFile) -> Option<&AnalyzerDelegate> {
        self.delegates.get(&self.dispatch_language(file))
    }

    /// The prepared syntax the analysis walk holds for `file`. Only Rust
    /// answers today; the differential reads Rust files alone.
    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn prepared_syntax_for_test(
        &self,
        file: &ProjectFile,
    ) -> Option<Arc<crate::analyzer::tree_sitter_analyzer::PreparedSyntaxTree>> {
        let delegate = self.delegate_for_file(file)?;
        let scope = AnalyzerQueryScope::new(delegate.analyzer());
        match delegate {
            AnalyzerDelegate::Rust(rust) => rust.prepared_syntax(scope.token(), file),
            _ => None,
        }
    }

    fn delegate_for_procedure(
        &self,
        workspace: &crate::analyzer::WorkspaceAnalyzer,
        procedure: &crate::analyzer::semantic::ProcedureHandle,
    ) -> Option<&AnalyzerDelegate> {
        let file = crate::analyzer::semantic::type_flow::file_for_locator(
            workspace,
            procedure.semantics().locator(),
        )?;
        if procedure.artifact().key().mount()
            != crate::analyzer::semantic::WorkspaceMountId::from_root(file.root())
        {
            return None;
        }
        self.delegate_for_file(&file)
    }

    pub(crate) fn program_semantics_provider_for_file(
        &self,
        file: &ProjectFile,
    ) -> Option<&dyn crate::analyzer::semantic::ProgramSemanticsProvider> {
        self.program_semantics_provider_context_for_file(file)
            .map(|(_, provider)| provider)
    }

    pub(crate) fn program_semantics_provider_context_for_file(
        &self,
        file: &ProjectFile,
    ) -> Option<(
        &dyn IAnalyzer,
        &dyn crate::analyzer::semantic::ProgramSemanticsProvider,
    )> {
        let delegate = self.delegate_for_file(file)?;
        Some((delegate.analyzer(), delegate.program_semantics_provider()))
    }

    fn delegate_for_code_unit(&self, code_unit: &CodeUnit) -> Option<&AnalyzerDelegate> {
        self.delegate_for_file(code_unit.source())
    }

    /// The Kotlin delegate, together with a view of the whole JVM source realm,
    /// when this workspace has Kotlin alongside at least one other JVM
    /// language.
    ///
    /// A Kotlin analyzer only indexes `.kt` files, so on its own it cannot see
    /// that the interface a Kotlin class implements is declared in a Java file
    /// next door. `MultiAnalyzer` is the only place that holds every delegate,
    /// so it is where the realm view is constructed. `None` means the widening
    /// would add nothing and the delegate's own answer already stands.
    fn kotlin_realm(&self) -> Option<(&KotlinAnalyzer, JvmSourceRealm<'_>)> {
        let Some(AnalyzerDelegate::Kotlin(kotlin)) = self.delegates.get(&Language::Kotlin) else {
            return None;
        };
        let realm = jvm_source_realm(self);
        realm
            .has_peers_of(Language::Kotlin)
            .then_some((kotlin, realm))
    }

    /// Union one lookup's answer across every delegate.
    ///
    /// Rayon's fan-out from a thread that is not already a pool worker injects
    /// the job into the global pool and parks the caller on a latch until a
    /// worker picks it up. That round trip is pure overhead for a workspace with
    /// one language, which is one delegate and therefore one job, and every
    /// symbol lookup paid it (#2115). Run the query inline in that case and fan
    /// out only when there is more than one delegate to spread. Both arms share
    /// this one definition so their results cannot drift.
    fn merged_from_delegates(
        &self,
        query: impl Fn(&dyn IAnalyzer) -> BTreeSet<CodeUnit> + Sync,
    ) -> BTreeSet<CodeUnit> {
        if self.delegates.len() <= 1 {
            let mut merged = BTreeSet::new();
            for delegate in self.delegates.values() {
                merged.extend(query(delegate.analyzer()));
            }
            return merged;
        }
        self.delegates
            .values()
            .collect::<Vec<_>>()
            .into_par_iter()
            .map(|delegate| query(delegate.analyzer()))
            .reduce(BTreeSet::new, |mut acc, found| {
                acc.extend(found);
                acc
            })
    }

    fn for_each_import_provider_group(
        &self,
        files: &[ProjectFile],
        cancellation: &crate::CancellationToken,
        mut visit: impl FnMut(&dyn ImportAnalysisProvider, &[ProjectFile]),
    ) {
        for (language, group) in group_files_by_language(files, language_for_file) {
            if cancellation.is_cancelled() {
                return;
            }
            let Some(provider) = self
                .delegates
                .get(&language)
                .and_then(AnalyzerDelegate::import_analysis_provider)
            else {
                continue;
            };
            visit(provider, &group);
        }
    }

    fn member_family_provider_for_code_unit(
        &self,
        member: &CodeUnit,
    ) -> Option<&dyn crate::analyzer::usages::MemberFamilyProvider> {
        self.delegate_for_code_unit(member)
            .and_then(|delegate| delegate.analyzer().member_family_provider())
    }

    fn any_delegate(&self, predicate: impl Fn(&AnalyzerDelegate) -> bool) -> bool {
        self.delegates.values().any(predicate)
    }
}

/// Record the importers answer for each file the caller asked about.
///
/// The answer is a whole-workspace relation: a new importer in a file the
/// reader never mentions changes it while no per-file key the reader recorded
/// moves. The digest is over workspace-relative paths only, so it is equal
/// across two checkouts of the same content.
///
/// The batch form records one key per target carrying the digest of the merged
/// answer rather than of that target's own share, because the merged set is
/// what the batch actually answered; over-recording is the sound direction.
fn record_importer_lookup(
    analyzer: &dyn IAnalyzer,
    targets: &[ProjectFile],
    referencing: &HashSet<ProjectFile>,
) {
    if !analyzer.read_ledger_attached() {
        return;
    }
    let digest = crate::analyzer::read_ledger::file_set_digest(referencing);
    for target in targets {
        analyzer.record_read(crate::analyzer::read_ledger::ReadKey::lookup(
            crate::analyzer::read_ledger::LookupKind::Importers,
            crate::analyzer::read_ledger::LookupQuestion::file(target),
            digest,
        ));
    }
}

impl ImportAnalysisProvider for MultiAnalyzer {
    fn imported_code_units_of(&self, file: &ProjectFile) -> Arc<HashSet<CodeUnit>> {
        let query_scope = AnalyzerQueryScope::new(self);
        let token = query_scope.token();
        // A Kotlin file can import a Java or Scala declaration from the same
        // workspace, and only the multi-analyzer can see both sides.
        if language_for_file(file) == Language::Kotlin
            && let Some((kotlin, realm)) = self.kotlin_realm()
        {
            return kotlin.imported_code_units_in_realm(token, file, Some(&realm));
        }
        self.delegate_for_file(file)
            .and_then(AnalyzerDelegate::import_analysis_provider)
            .map(|provider| provider.imported_code_units_of(file))
            .unwrap_or_default()
    }

    fn referencing_files_of(&self, file: &ProjectFile) -> HashSet<ProjectFile> {
        let referencing: HashSet<ProjectFile> = self
            .delegates
            .values()
            .filter_map(AnalyzerDelegate::import_analysis_provider)
            .flat_map(|provider| provider.referencing_files_of(file))
            .collect();
        record_importer_lookup(self, std::slice::from_ref(file), &referencing);
        referencing
    }

    fn referencing_files_of_targets(
        &self,
        targets: &HashSet<ProjectFile>,
        cancellation: &crate::CancellationToken,
    ) -> HashSet<ProjectFile> {
        let mut referencing = HashSet::default();
        for provider in self
            .delegates
            .values()
            .filter_map(AnalyzerDelegate::import_analysis_provider)
        {
            if cancellation.is_cancelled() {
                break;
            }
            referencing.extend(provider.referencing_files_of_targets(targets, cancellation));
        }
        if IAnalyzer::read_ledger_attached(self) {
            let targets = targets.iter().cloned().collect::<Vec<_>>();
            record_importer_lookup(self, &targets, &referencing);
        }
        referencing
    }

    fn import_info_of(&self, token: QueryToken<'_>, file: &ProjectFile) -> Vec<ImportInfo> {
        self.import_analysis_provider_for_file(file)
            .map(|provider| provider.import_info_of(token, file))
            .unwrap_or_default()
    }

    fn import_info_of_checked(
        &self,
        token: QueryToken<'_>,
        file: &ProjectFile,
    ) -> Option<Vec<ImportInfo>> {
        self.import_analysis_provider_for_file(file)
            .and_then(|provider| provider.import_info_of_checked(token, file))
    }

    fn import_infos_for_files(
        &self,
        files: &[ProjectFile],
    ) -> Option<HashMap<ProjectFile, Vec<ImportInfo>>> {
        let query_scope = AnalyzerQueryScope::new(self);
        let token = query_scope.token();
        if files.is_empty() {
            return None;
        }
        // Route each file to its language delegate and prefer that delegate's
        // bulk reader (one store round-trip for the whole group) over the
        // per-file `import_info_of` path the shared candidate walker would
        // otherwise take. Delegates without a bulk model fall back to per-file
        // reads within their own group so the merged map still covers every
        // file, keeping the caller's result identical to the file-at-a-time
        // path while collapsing thousands of single-row queries into one.
        let grouped = group_files_by_language(files, |file| self.dispatch_language(file));
        let mut out: HashMap<ProjectFile, Vec<ImportInfo>> = HashMap::default();
        let mut any = false;
        for (language, group) in grouped {
            let Some(provider) = self
                .delegates
                .get(&language)
                .and_then(AnalyzerDelegate::import_analysis_provider)
            else {
                continue;
            };
            any = true;
            if let Some(map) = provider.import_infos_for_files(&group) {
                out.extend(map);
            } else {
                for file in group {
                    let infos = provider.import_info_of(token, &file);
                    out.insert(file, infos);
                }
            }
        }
        any.then_some(out)
    }

    fn file_dependency_facts_for_files(
        &self,
        files: &[ProjectFile],
    ) -> Option<HashMap<ProjectFile, FileDependencyFacts>> {
        if files.is_empty() {
            return None;
        }
        let grouped = group_files_by_language(files, |file| self.dispatch_language(file));
        let mut out = HashMap::default();
        let mut any = false;
        for (language, group) in grouped {
            let Some(provider) = self
                .delegates
                .get(&language)
                .and_then(AnalyzerDelegate::import_analysis_provider)
            else {
                continue;
            };
            any = true;
            if let Some(facts) = provider.file_dependency_facts_for_files(&group) {
                out.extend(facts);
            }
        }
        any.then_some(out)
    }

    fn additional_direct_file_dependencies(
        &self,
        files: &[ProjectFile],
        cancellation: &crate::CancellationToken,
    ) -> Option<AdditionalFileDependencies> {
        let grouped = group_files_by_language(files, |file| self.dispatch_language(file));
        let mut out: HashMap<ProjectFile, HashSet<ProjectFile>> = HashMap::default();
        let mut complete = true;
        for (language, group) in grouped {
            if cancellation.is_cancelled() {
                return None;
            }
            let Some(provider) = self
                .delegates
                .get(&language)
                .and_then(AnalyzerDelegate::import_analysis_provider)
            else {
                continue;
            };
            let Some(outcome) = provider.additional_direct_file_dependencies(&group, cancellation)
            else {
                if cancellation.is_cancelled() {
                    return None;
                }
                complete = false;
                continue;
            };
            complete &= outcome.complete;
            for (file, targets) in outcome.dependencies {
                out.entry(file).or_default().extend(targets);
            }
        }
        Some(if complete {
            AdditionalFileDependencies::complete(out)
        } else {
            AdditionalFileDependencies::incomplete(out)
        })
    }

    fn relevant_imports_for(&self, code_unit: &CodeUnit) -> HashSet<String> {
        self.delegate_for_code_unit(code_unit)
            .and_then(AnalyzerDelegate::import_analysis_provider)
            .map(|provider| provider.relevant_imports_for(code_unit))
            .unwrap_or_default()
    }

    fn could_import_file(
        &self,
        source_file: &ProjectFile,
        imports: &[ImportInfo],
        target: &ProjectFile,
    ) -> bool {
        self.delegate_for_file(source_file)
            .and_then(AnalyzerDelegate::import_analysis_provider)
            .map(|provider| provider.could_import_file(source_file, imports, target))
            .unwrap_or(false)
    }

    /// The batch that `could_import_file` above is meant to be answered from.
    ///
    /// Without this override the trait's no-op default answers, so a delegate's
    /// own batch -- `RustAnalyzer::prefetch_import_targets`, and the single
    /// chunked seek it stands for -- never runs on a workspace with more than
    /// one language, which is every workspace #1748 was opened about. Measured
    /// at `0086f1e5` on the rustc tree: zero `prefetch_definitions` spans in a
    /// scan whose candidate discovery took 9,648 point `definition_candidates`
    /// reads.
    ///
    /// Grouping is the same as `import_infos_for_files` above, for the same
    /// reason: the question is per language and only that language's delegate
    /// can answer it. `import_infos` goes through whole rather than split per
    /// group -- a delegate reads it by the file keys it was handed, so a subset
    /// would only cost a copy.
    ///
    /// Between groups is the one place this layer can stop. It polls there
    /// because a group is one batched read and the deadline may have expired
    /// during the previous one; it publishes nothing itself, so stopping leaves
    /// each delegate's request memo exactly as that delegate left it -- the
    /// prefix of a cut-short batch is never memoized as absence.
    fn prefetch_import_targets(
        &self,
        files: &[ProjectFile],
        import_infos: Option<&HashMap<ProjectFile, Vec<ImportInfo>>>,
        cancellation: &crate::CancellationToken,
    ) {
        self.for_each_import_provider_group(files, cancellation, |provider, group| {
            provider.prefetch_import_targets(group, import_infos, cancellation);
        });
    }

    fn prefetch_file_dependency_targets(
        &self,
        files: &[ProjectFile],
        import_infos: Option<&HashMap<ProjectFile, Vec<ImportInfo>>>,
        cancellation: &crate::cancellation::CancellationToken,
    ) {
        self.for_each_import_provider_group(files, cancellation, |provider, group| {
            provider.prefetch_file_dependency_targets(group, import_infos, cancellation);
        });
    }

    /// A file whose language has no delegate is undecided, not unreachable:
    /// `unwrap_or` must not manufacture a proof the workspace never made.
    fn import_reachability(
        &self,
        source_file: &ProjectFile,
        imports: &[ImportInfo],
        target: &ProjectFile,
    ) -> ImportReachability {
        self.delegate_for_file(source_file)
            .and_then(AnalyzerDelegate::import_analysis_provider)
            .map(|provider| provider.import_reachability(source_file, imports, target))
            .unwrap_or(ImportReachability::Unknown)
    }

    /// Without this override, `MultiAnalyzer` falls back to the trait default (always `None`) instead
    /// of forwarding to the per-language delegate's implementation -- silently defeating a delegate's
    /// own `imported_code_units_from_infos` (e.g. Python's) for every workspace-level caller that goes
    /// through `MultiAnalyzer`, which is the common case for a `scan_usages` on a real checkout.
    fn imported_code_units_from_infos(
        &self,
        file: &ProjectFile,
        imports: &[ImportInfo],
    ) -> Option<Arc<HashSet<CodeUnit>>> {
        self.import_analysis_provider_for_file(file)
            .and_then(|provider| provider.imported_code_units_from_infos(file, imports))
    }

    /// Same omission as the method above, one rung further down: without this
    /// override `resolve_imported_files_from_infos` gets the trait default
    /// `None` and degrades to projecting imported *declarations* back to their
    /// files. An import whose target file declares nothing -- a Ruby
    /// `require_relative` loader, say -- then contributes no file edge at all,
    /// so transitive-importer candidate discovery never reaches the files that
    /// require it. Routing per file is the correct composition: `imports` always
    /// comes from `import_info_of`, which routes through the same
    /// `delegate_for_file`, so the two answers stay consistent.
    fn imported_files_from_infos(
        &self,
        file: &ProjectFile,
        imports: &[ImportInfo],
    ) -> Option<HashSet<ProjectFile>> {
        self.import_analysis_provider_for_file(file)
            .and_then(|provider| provider.imported_files_from_infos(file, imports))
    }
}

impl TypeHierarchyProvider for MultiAnalyzer {
    fn supports_type_hierarchy(&self, code_unit: &CodeUnit) -> bool {
        self.delegate_for_code_unit(code_unit)
            .and_then(AnalyzerDelegate::type_hierarchy_provider)
            .is_some_and(|provider| provider.supports_type_hierarchy(code_unit))
    }

    fn get_direct_ancestors(&self, code_unit: &CodeUnit) -> Vec<CodeUnit> {
        let query_scope = AnalyzerQueryScope::new(self);
        let token = query_scope.token();
        // A Kotlin class can extend a Java class or implement a Scala trait
        // declared in the same workspace; resolving that needs every JVM
        // delegate, which only the multi-analyzer holds.
        if language_for_file(code_unit.source()) == Language::Kotlin
            && let Some((kotlin, realm)) = self.kotlin_realm()
        {
            return kotlin.direct_ancestors_in_realm(token, code_unit, Some(&realm));
        }
        self.delegate_for_code_unit(code_unit)
            .and_then(AnalyzerDelegate::type_hierarchy_provider)
            .map(|provider| provider.get_direct_ancestors(code_unit))
            .unwrap_or_default()
    }

    fn get_direct_descendants(&self, code_unit: &CodeUnit) -> HashSet<CodeUnit> {
        crate::analyzer::whole_workspace_descendants(|scope| {
            self.get_direct_descendants_within(code_unit, scope)
        })
    }

    fn get_direct_ancestors_within(
        &self,
        code_unit: &CodeUnit,
        scope: &crate::analyzer::DescendantIndexScope<'_>,
    ) -> Option<Vec<CodeUnit>> {
        let query_scope = AnalyzerQueryScope::new(self);
        let token = query_scope.token();
        if language_for_file(code_unit.source()) == Language::Kotlin
            && let Some((kotlin, realm)) = self.kotlin_realm()
        {
            return (!scope.cancellation().is_cancelled())
                .then(|| kotlin.direct_ancestors_in_realm(token, code_unit, Some(&realm)));
        }
        match self
            .delegate_for_code_unit(code_unit)
            .and_then(AnalyzerDelegate::type_hierarchy_provider)
        {
            Some(provider) => provider.get_direct_ancestors_within(code_unit, scope),
            None => Some(Vec::new()),
        }
    }

    fn get_direct_descendants_within(
        &self,
        code_unit: &CodeUnit,
        scope: &crate::analyzer::DescendantIndexScope<'_>,
    ) -> Option<HashSet<CodeUnit>> {
        let query_scope = AnalyzerQueryScope::new(self);
        let token = query_scope.token();
        let mut descendants = match self
            .delegate_for_code_unit(code_unit)
            .and_then(AnalyzerDelegate::type_hierarchy_provider)
        {
            Some(provider) => provider.get_direct_descendants_within(code_unit, scope)?,
            None => HashSet::default(),
        };
        // Kotlin subclasses of a Java or Scala type are invisible to that
        // language's own descendant index, which only walks its own
        // declarations. Kotlin's realm-aware index does resolve across the
        // realm, so folding it in is what makes `Api`'s Kotlin implementors
        // show up.
        //
        // The reverse direction — Java and Scala subclasses of a *Kotlin* type
        // — is still missing, and cannot be fixed here. Each language's
        // descendant index is the inverse of its own ancestor resolution, and
        // Java's and Scala's resolve a spelled supertype against their own
        // declarations only; folding their indexes in for a Kotlin unit would
        // fold in indexes that never saw the Kotlin declaration in the first
        // place. Closing it means giving those two hierarchy resolvers the
        // realm-aware existence predicate Kotlin's already has (`realm_type_exists`
        // / `realm_type_by_fqn` in `kotlin/hierarchy.rs`) — a change to those
        // analyzers, not to this dispatch. Issue #1239 made *usage* resolution
        // realm-aware in both directions; hierarchy resolution is a separate
        // seam and remains one-directional.
        if language_for_file(code_unit.source()) != Language::Kotlin
            && let Some((kotlin, realm)) = self.kotlin_realm()
        {
            descendants.extend(kotlin.direct_descendants_in_realm(
                token,
                code_unit,
                Some(&realm),
                scope,
            )?);
        }
        if IAnalyzer::read_ledger_attached(self) {
            // Descendants are a cross-file answer: a subclass added in a file
            // the reader never mentions changes it, and no per-file key the
            // reader recorded moves.
            self.record_read(crate::analyzer::read_ledger::ReadKey::lookup(
                crate::analyzer::read_ledger::LookupKind::Descendants,
                crate::analyzer::read_ledger::LookupQuestion::declaration(code_unit),
                crate::analyzer::read_ledger::declaration_set_digest(&descendants),
            ));
        }
        Some(descendants)
    }
}

/// Method families across the whole workspace (#1477 M4).
///
/// The delegation mirrors `TypeHierarchyProvider`'s, and for the same reason:
/// a Kotlin class can override a Java method, so the ancestor and descendant
/// edges a family walk needs are exactly the realm-aware ones only the
/// multi-analyzer resolves. The per-language relation therefore receives
/// `self` as its hierarchy source rather than the owning delegate.
///
/// Language support is stated per member, never defaulted: a member whose
/// language has no landed family answers `unsupported`, even though this
/// composite exposes a provider for the workspace as a whole.
/// Java and Scala keep explicit arms because their relations need the
/// *composite* hierarchy: a Kotlin class can extend a Java class and a Scala
/// class can extend a Java class, so passing `self` as the hierarchy source is
/// the whole reason the relation takes it separately.
///
/// Every other language's family is answered by its own delegate. That is what
/// a structural relation like Go's requires -- its satisfaction index is built
/// from Go sources alone -- and it is also right for C#, whose types no other
/// realm can extend.
impl crate::analyzer::usages::MemberFamilyProvider for MultiAnalyzer {
    fn member_family_capability(
        &self,
        member: &CodeUnit,
    ) -> crate::analyzer::structural::resolution::MemberFamilyCapability {
        match language_for_file(member.source()) {
            Language::Java => crate::analyzer::usages::java_member_family_capability(self, member),
            Language::Scala => {
                crate::analyzer::usages::scala_member_family_capability(self, member)
            }
            _ => self
                .member_family_provider_for_code_unit(member)
                .map(|provider| provider.member_family_capability(member))
                .unwrap_or(
                    crate::analyzer::structural::resolution::MemberFamilyCapability::Unsupported,
                ),
        }
    }

    fn member_family(
        &self,
        member: &CodeUnit,
        cancellation: Option<&crate::cancellation::CancellationToken>,
    ) -> crate::analyzer::usages::MemberFamilyAnswer {
        match language_for_file(member.source()) {
            Language::Java => {
                crate::analyzer::usages::java_member_family(self, self, member, cancellation)
            }
            Language::Scala => {
                crate::analyzer::usages::scala_member_family(self, self, member, cancellation)
            }
            _ => self
                .member_family_provider_for_code_unit(member)
                .map(|provider| provider.member_family(member, cancellation))
                .unwrap_or_else(crate::analyzer::usages::MemberFamilyAnswer::unsupported_answer),
        }
    }

    fn external_member_family(
        &self,
        identity: &brokk_bifrost_jvm::realm::JvmExternalMemberIdentity,
        max_visits: usize,
        cancellation: Option<&crate::cancellation::CancellationToken>,
    ) -> crate::analyzer::usages::ExternalMemberFamilyAnswer {
        // A call site's identity carries the language of the analyzer that
        // published the boundary, so each JVM analyzer answers for its own call
        // sites. Every arm refuses a mixed realm the same way: one language's
        // supertype facts alone cannot enumerate the other language's
        // declarations, a Kotlin class can extend a Java class (and the
        // reverse), and a Scala class can extend either, so no arm may prove
        // the boundary from one analyzer's tree alone (#3452, #3453, #3454).
        if identity.language() == Language::Kotlin {
            if let Some(language) = [Language::Java, Language::Scala]
                .into_iter()
                .find(|language| self.languages().contains(language))
            {
                return crate::analyzer::usages::ExternalMemberFamilyAnswer::incomplete(
                    crate::analyzer::usages::ExternalMemberFamilyIncompleteReason::MixedJvmRealmUnsupported(
                        language,
                    ),
                    0,
                );
            }
            let Some(kotlin) = resolve_analyzer::<KotlinAnalyzer>(self) else {
                return crate::analyzer::usages::ExternalMemberFamilyAnswer::unsupported();
            };
            return kotlin.resolve_external_member_family(self, identity, max_visits, cancellation);
        }
        if identity.language() == Language::Scala {
            if let Some(language) = [Language::Java, Language::Kotlin]
                .into_iter()
                .find(|language| self.languages().contains(language))
            {
                return crate::analyzer::usages::ExternalMemberFamilyAnswer::incomplete(
                    crate::analyzer::usages::ExternalMemberFamilyIncompleteReason::MixedJvmRealmUnsupported(
                        language,
                    ),
                    0,
                );
            }
            let Some(scala) = resolve_analyzer::<ScalaAnalyzer>(self) else {
                return crate::analyzer::usages::ExternalMemberFamilyAnswer::unsupported();
            };
            return scala.resolve_external_member_family(self, identity, max_visits, cancellation);
        }
        if identity.language() != Language::Java {
            return crate::analyzer::usages::ExternalMemberFamilyAnswer::unsupported();
        }
        if let Some(language) = [Language::Kotlin, Language::Scala]
            .into_iter()
            .find(|language| self.languages().contains(language))
        {
            return crate::analyzer::usages::ExternalMemberFamilyAnswer::incomplete(
                crate::analyzer::usages::ExternalMemberFamilyIncompleteReason::MixedJvmRealmUnsupported(
                    language,
                ),
                0,
            );
        }
        let Some(java) = resolve_analyzer::<JavaAnalyzer>(self) else {
            return crate::analyzer::usages::ExternalMemberFamilyAnswer::unsupported();
        };
        java.resolve_external_member_family(self, identity, max_visits, cancellation)
    }
}

impl TypeAliasProvider for MultiAnalyzer {
    fn is_type_alias(&self, code_unit: &CodeUnit) -> bool {
        self.delegate_for_code_unit(code_unit)
            .and_then(AnalyzerDelegate::type_alias_provider)
            .map(|provider| provider.is_type_alias(code_unit))
            .unwrap_or(false)
    }
}

impl TestDetectionProvider for MultiAnalyzer {}

use crate::analyzer::CodeUnitIndex;

impl CodeUnitIndex for MultiAnalyzer {
    fn enclosing_code_unit(&self, file: &ProjectFile, range: &Range) -> Option<CodeUnit> {
        self.delegate_for_file(file)
            .and_then(|delegate| delegate.analyzer().enclosing_code_unit(file, range))
    }

    fn enclosing_code_unit_for_lines(
        &self,
        file: &ProjectFile,
        start_line: usize,
        end_line: usize,
    ) -> Option<CodeUnit> {
        self.delegate_for_file(file).and_then(|delegate| {
            delegate
                .analyzer()
                .enclosing_code_unit_for_lines(file, start_line, end_line)
        })
    }

    fn top_level_declarations(&self, file: &ProjectFile) -> Vec<CodeUnit> {
        delegate_or_default(self.delegate_for_file(file), |analyzer| {
            analyzer.top_level_declarations(file)
        })
    }

    fn summary_file_projection(&self, file: &ProjectFile) -> Option<Arc<SummaryFileProjection>> {
        self.delegate_for_file(file)
            .and_then(|delegate| delegate.analyzer().summary_file_projection(file))
    }

    fn analyzed_files(&self) -> Vec<ProjectFile> {
        // One visible parent for the per-language fan-out: on an 11-language
        // workspace this is 11 whole-workspace scans and 11 store queries, and
        // #1738's worst route span held nothing but this (uninstrumented).
        let _scope = crate::profiling::scope("analyzer::analyzed_files.fan_out");
        let mut files: Vec<_> = self
            .delegates
            .values()
            .flat_map(|delegate| delegate.analyzer().analyzed_files())
            .collect();
        files.sort();
        files.dedup();
        files
    }

    /// Goes straight to the delegate that owns `language` instead of the
    /// default's fan-out-every-language-then-filter, which would otherwise
    /// re-pay the whole-workspace, every-language scan and sort above for an
    /// answer only this one (already single-language) delegate can give
    /// directly (issue #1738's shape, one call site further out -- see
    /// `CodeUnitIndex::analyzed_files_for_language`'s default).
    ///
    /// Memoized per language: a caller that asks this once per candidate
    /// declaration -- once per ambiguous target's every overload, on a
    /// workspace with heavy same-name duplication -- would otherwise still
    /// re-sort the same (already single-language) file list from scratch on
    /// every call. `analyzed_files_by_language` shares `snapshot_caches`'s
    /// lifetime: valid as long as this snapshot is (bifrost#15).
    fn analyzed_files_for_language(&self, language: Language) -> Vec<ProjectFile> {
        if !self.delegates.contains_key(&language) {
            return Vec::new();
        }
        let cell = self.analyzed_files_by_language.cell(&language);
        let build = || {
            let mut files = self
                .delegates
                .get(&language)
                .map(|delegate| delegate.analyzer().analyzed_files())
                .unwrap_or_default();
            files.sort();
            files
        };
        (*cell.get_or_build(build, build)).clone()
    }

    fn indexed_source(&self, file: &ProjectFile) -> Option<String> {
        self.delegate_for_file(file)
            .and_then(|delegate| delegate.analyzer().indexed_source(file))
    }

    fn location_declarations(&self, file: &ProjectFile) -> BTreeSet<CodeUnit> {
        delegate_or_default(self.delegate_for_file(file), |analyzer| {
            analyzer.location_declarations(file)
        })
    }

    fn location_ranges(&self, code_unit: &CodeUnit) -> Vec<Range> {
        self.delegate_for_code_unit(code_unit)
            .map(|delegate| delegate.analyzer().location_ranges(code_unit))
            .unwrap_or_default()
    }

    fn indexed_source_matches(&self, file: &ProjectFile, source: &str) -> bool {
        self.delegate_for_file(file)
            .is_some_and(|delegate| delegate.analyzer().indexed_source_matches(file, source))
    }

    fn render_source_fragment(
        &self,
        code_unit: &CodeUnit,
        source: String,
        declaration_start: usize,
    ) -> String {
        match self.delegate_for_code_unit(code_unit) {
            Some(delegate) => {
                delegate
                    .analyzer()
                    .render_source_fragment(code_unit, source, declaration_start)
            }
            None => source,
        }
    }

    fn is_analyzed(&self, file: &ProjectFile) -> bool {
        self.delegates
            .values()
            .any(|delegate| delegate.analyzer().is_analyzed(file))
    }

    /// Every delegate sees the whole candidate list and keeps the ones it owns,
    /// so the workspace answer costs one store query per language over the
    /// matched files -- not one whole-workspace enumeration per language, which
    /// is what asking `analyzed_files` here used to cost (#1738).
    fn retain_analyzed(&self, candidates: &[ProjectFile]) -> Vec<ProjectFile> {
        let mut analyzed: Vec<_> = self
            .delegates
            .values()
            .flat_map(|delegate| delegate.analyzer().retain_analyzed(candidates))
            .collect();
        analyzed.sort();
        analyzed.dedup();
        analyzed
    }

    fn languages(&self) -> BTreeSet<Language> {
        self.delegates.keys().copied().collect()
    }

    fn project(&self) -> &dyn Project {
        self.delegates
            .values()
            .next()
            .expect("MultiAnalyzer requires at least one delegate")
            .analyzer()
            .project()
    }

    fn all_declarations(&self) -> Box<dyn Iterator<Item = CodeUnit> + '_> {
        Box::new(
            self.delegates
                .values()
                .flat_map(|delegate| delegate.analyzer().all_declarations()),
        )
    }

    fn all_declarations_with_primary_ranges(&self) -> Vec<(CodeUnit, Option<Range>)> {
        self.delegates
            .values()
            .flat_map(|delegate| delegate.analyzer().all_declarations_with_primary_ranges())
            .collect()
    }

    fn declarations(&self, file: &ProjectFile) -> BTreeSet<CodeUnit> {
        delegate_or_default(self.delegate_for_file(file), |analyzer| {
            analyzer.declarations(file)
        })
    }

    fn declares(&self, file: &ProjectFile, unit: &CodeUnit) -> bool {
        self.delegate_for_file(file)
            .is_some_and(|delegate| delegate.analyzer().declares(file, unit))
    }

    /// Routed to the owning delegate so its request-scoped memo answers
    /// (#2679); the trait default on `self` would rebuild uncached per call.
    fn class_range_index(
        &self,
        file: &ProjectFile,
    ) -> Arc<brokk_bifrost_core::analyzer::usages::inverted_edges::ClassRangeIndex> {
        match self.delegate_for_file(file) {
            Some(delegate) => delegate.analyzer().class_range_index(file),
            None => Arc::new(
                brokk_bifrost_core::analyzer::usages::inverted_edges::ClassRangeIndex::from_class_spans(
                    std::iter::empty(),
                ),
            ),
        }
    }

    fn materialization_records(
        &self,
        file: &ProjectFile,
    ) -> Vec<crate::analyzer::structural::materialization::MaterializationRecord> {
        match self.delegate_for_file(file) {
            Some(delegate) => delegate.analyzer().materialization_records(file),
            None => Vec::new(),
        }
    }

    fn parse_completeness(&self, file: &ProjectFile) -> crate::analyzer::ParseCompleteness {
        match self.delegate_for_file(file) {
            Some(delegate) => delegate.analyzer().parse_completeness(file),
            None => crate::analyzer::ParseCompleteness::Complete,
        }
    }

    /// Every delegate, not the one that owns `unit`: the workspace scan this
    /// replaces spanned every language, so a name declared as a module in two
    /// of them stayed visible in both.
    fn declarations_sharing_name(&self, unit: &CodeUnit) -> Vec<CodeUnit> {
        self.delegates
            .values()
            .flat_map(|delegate| delegate.analyzer().declarations_sharing_name(unit))
            .collect()
    }

    fn definitions(&self, fq_name: &str) -> Box<dyn Iterator<Item = CodeUnit> + '_> {
        let matches: Vec<_> = self
            .delegates
            .iter()
            .flat_map(|(language, delegate)| {
                let _scope = crate::profiling::scope_with(|| {
                    format!("multi.definitions[{language:?}][{fq_name}]")
                });
                delegate.analyzer().definitions(fq_name)
            })
            .collect();
        if IAnalyzer::read_ledger_attached(self) {
            self.record_read(crate::analyzer::read_ledger::ReadKey::lookup(
                crate::analyzer::read_ledger::LookupKind::Definitions,
                crate::analyzer::read_ledger::LookupQuestion::Name {
                    language: None,
                    name: fq_name.into(),
                },
                crate::analyzer::read_ledger::declaration_set_digest(&matches),
            ));
        }
        Box::new(matches.into_iter())
    }

    fn prefetch_definitions(&self, fq_names: &[String]) {
        self.prefetch_delegates(fq_names);
    }

    fn direct_children(&self, code_unit: &CodeUnit) -> Vec<CodeUnit> {
        match self.delegate_for_code_unit(code_unit) {
            Some(delegate) => delegate.analyzer().direct_children(code_unit),
            None => Vec::new(),
        }
    }

    fn direct_children_in_file(&self, code_unit: &CodeUnit) -> Vec<CodeUnit> {
        match self.delegate_for_code_unit(code_unit) {
            Some(delegate) => delegate.analyzer().direct_children_in_file(code_unit),
            None => Vec::new(),
        }
    }

    fn parent_of(&self, code_unit: &CodeUnit) -> Option<CodeUnit> {
        self.delegate_for_code_unit(code_unit)
            .and_then(|delegate| delegate.analyzer().parent_of(code_unit))
    }

    fn ranges(&self, code_unit: &CodeUnit) -> Vec<Range> {
        self.delegate_for_code_unit(code_unit)
            .map(|delegate| delegate.analyzer().ranges(code_unit))
            .unwrap_or_default()
    }

    fn ranges_with_limit(
        &self,
        code_unit: &CodeUnit,
        max_ranges: usize,
        cancellation: &crate::CancellationToken,
    ) -> (Vec<Range>, usize, bool) {
        self.delegate_for_code_unit(code_unit)
            .map(|delegate| {
                delegate
                    .analyzer()
                    .ranges_with_limit(code_unit, max_ranges, cancellation)
            })
            .unwrap_or_default()
    }

    fn get_skeleton(&self, code_unit: &CodeUnit) -> Option<String> {
        self.delegate_for_code_unit(code_unit)
            .and_then(|delegate| delegate.analyzer().get_skeleton(code_unit))
    }

    fn get_skeleton_header(&self, code_unit: &CodeUnit) -> Option<String> {
        self.delegate_for_code_unit(code_unit)
            .and_then(|delegate| delegate.analyzer().get_skeleton_header(code_unit))
    }

    fn get_source(&self, code_unit: &CodeUnit, include_comments: bool) -> Option<String> {
        self.delegate_for_code_unit(code_unit)
            .and_then(|delegate| delegate.analyzer().get_source(code_unit, include_comments))
    }

    fn get_sources(&self, code_unit: &CodeUnit, include_comments: bool) -> BTreeSet<String> {
        self.delegate_for_code_unit(code_unit)
            .map(|delegate| delegate.analyzer().get_sources(code_unit, include_comments))
            .unwrap_or_default()
    }

    fn search_definitions(&self, pattern: &str, auto_quote: bool) -> BTreeSet<CodeUnit> {
        self.merged_from_delegates(|analyzer| analyzer.search_definitions(pattern, auto_quote))
    }

    fn search_definitions_by_suffix_pattern(
        &self,
        pattern: &str,
        terminal_identifiers: &[String],
        language: Language,
    ) -> BTreeSet<CodeUnit> {
        // The pattern is language-specific, so only that language's delegate
        // can produce matches the caller keeps; fanning out to every delegate
        // multiplied lookup cost by the language count (#1430).
        self.delegates
            .get(&language)
            .map(|delegate| {
                delegate.analyzer().search_definitions_by_suffix_pattern(
                    pattern,
                    terminal_identifiers,
                    language,
                )
            })
            .unwrap_or_default()
    }

    fn lookup_candidates_by_short_name(&self, symbol: &str) -> BTreeSet<CodeUnit> {
        let matches =
            self.merged_from_delegates(|analyzer| analyzer.lookup_candidates_by_short_name(symbol));
        if IAnalyzer::read_ledger_attached(self) {
            self.record_read(
                crate::analyzer::read_ledger::declaration_candidates_lookup_key(
                    crate::analyzer::read_ledger::LookupKind::ShortNameCandidates,
                    None,
                    symbol,
                    &matches,
                ),
            );
        }
        matches
    }

    /// Every delegate must be able to answer from an index before a miss is
    /// conclusive: one in-memory delegate's incomplete view would make a
    /// qualified miss mean "not in the indexed languages", not "not in the
    /// workspace".
    fn has_complete_symbol_lookup_index(&self) -> bool {
        self.delegates
            .values()
            .all(|delegate| delegate.analyzer().has_complete_symbol_lookup_index())
    }

    fn lookup_candidates_by_identifier(&self, identifier: &str) -> BTreeSet<CodeUnit> {
        let matches = self
            .merged_from_delegates(|analyzer| analyzer.lookup_candidates_by_identifier(identifier));
        if IAnalyzer::read_ledger_attached(self) {
            self.record_read(
                crate::analyzer::read_ledger::declaration_candidates_lookup_key(
                    crate::analyzer::read_ledger::LookupKind::IdentifierCandidates,
                    None,
                    identifier,
                    &matches,
                ),
            );
        }
        matches
    }

    fn search_definitions_persisted(&self, pattern: &str) -> BTreeSet<CodeUnit> {
        // Fan out to each delegate's `search_definitions_persisted` so the
        // FTS5 path is consulted per-language. The default impl on
        // `IAnalyzer` would otherwise re-dispatch through our own
        // `search_definitions` override, which only hits in-memory state.
        self.merged_from_delegates(|analyzer| analyzer.search_definitions_persisted(pattern))
    }

    fn signatures(&self, code_unit: &CodeUnit) -> Vec<String> {
        delegate_or_default(self.delegate_for_code_unit(code_unit), |analyzer| {
            analyzer.signatures(code_unit)
        })
    }

    fn signature_metadata(&self, code_unit: &CodeUnit) -> Vec<SignatureMetadata> {
        delegate_or_default(self.delegate_for_code_unit(code_unit), |analyzer| {
            analyzer.signature_metadata(code_unit)
        })
    }
}

impl IAnalyzer for MultiAnalyzer {
    fn dynamic_import_sources(
        &self,
        seed_files: Option<&[ProjectFile]>,
    ) -> std::result::Result<Vec<(String, String)>, crate::analyzer::store::StoreError> {
        let Some(context) = &self.build_context else {
            return Ok(Vec::new());
        };
        let seed_paths = seed_files.map(|files| {
            files
                .iter()
                .map(|file| {
                    (
                        file.language().config_label().to_owned(),
                        crate::path_utils::rel_path_string(file),
                    )
                })
                .collect::<Vec<_>>()
        });
        context
            .store_context
            .store
            .read_dynamic_import_sources(&context.store_context.workspace_id, seed_paths.as_deref())
    }

    fn loop_candidates_for(
        &self,
        workspace: &crate::analyzer::WorkspaceAnalyzer,
        procedure: &crate::analyzer::semantic::ProcedureHandle,
        cancellation: Option<&crate::CancellationToken>,
    ) -> Result<Arc<crate::analyzer::LoopCandidates>, crate::analyzer::QueryReadIncomplete> {
        match self.delegate_for_procedure(workspace, procedure) {
            Some(delegate) => {
                delegate
                    .analyzer()
                    .loop_candidates_for(workspace, procedure, cancellation)
            }
            None => Ok(Arc::new(crate::analyzer::build_loop_candidates(
                workspace,
                procedure,
                cancellation,
            ))),
        }
    }

    fn statement_assessments_for(
        &self,
        workspace: &crate::analyzer::WorkspaceAnalyzer,
        procedure: &crate::analyzer::semantic::ProcedureHandle,
        cancellation: Option<&crate::CancellationToken>,
    ) -> Arc<crate::analyzer::semantic::StatementAssessments> {
        match self.delegate_for_procedure(workspace, procedure) {
            Some(delegate) => {
                delegate
                    .analyzer()
                    .statement_assessments_for(workspace, procedure, cancellation)
            }
            None => Arc::new(
                crate::analyzer::semantic::statement_entries::build_statement_assessments(
                    workspace,
                    procedure,
                    cancellation,
                ),
            ),
        }
    }

    fn cpp_expression_source_facts(
        &self,
        file: &ProjectFile,
    ) -> Option<Arc<brokk_bifrost_core::analyzer::cpp_facts::CppExpressionSourceFacts>> {
        self.delegate_for_file(file)
            .and_then(|delegate| delegate.analyzer().cpp_expression_source_facts(file))
    }

    fn cpp_statement_source_facts(
        &self,
        file: &ProjectFile,
    ) -> Option<Arc<brokk_bifrost_core::analyzer::statement_facts::CppStatementFactRows>> {
        (language_for_file(file) == Language::Cpp)
            .then(|| self.delegate_for_file(file))
            .flatten()
            .and_then(|delegate| delegate.analyzer().cpp_statement_source_facts(file))
    }

    fn cpp_class_source_facts(
        &self,
        file: &ProjectFile,
    ) -> Option<Arc<brokk_bifrost_core::analyzer::cpp_facts::CppClassFactRows>> {
        self.delegate_for_file(file)
            .and_then(|delegate| delegate.analyzer().cpp_class_source_facts(file))
    }

    fn cpp_class_declaration_source_facts(
        &self,
        token: QueryToken<'_>,
        file: &ProjectFile,
    ) -> Option<Arc<Vec<brokk_bifrost_core::analyzer::cpp_facts::CppDeclarationSourceFact>>> {
        self.delegate_for_file(file).and_then(|delegate| {
            delegate
                .analyzer()
                .cpp_class_declaration_source_facts(token, file)
        })
    }

    fn dependency_file_locations(
        &self,
    ) -> crate::analyzer::store::Result<
        Vec<(
            String,
            crate::analyzer::semantic_model::DependencyEvidenceLocation,
        )>,
    > {
        let mut result = Vec::new();
        for delegate in self.delegates.values() {
            result.extend(delegate.analyzer().dependency_file_locations()?);
        }
        Ok(result)
    }

    fn dependency_file_evidence(
        &self,
    ) -> crate::analyzer::store::Result<crate::analyzer::semantic_model::DependencyFileEvidence>
    {
        use crate::analyzer::semantic_model::{
            DependencyEvidenceGap, DependencyEvidenceGapKind, DependencyFileEvidence,
        };
        let mut result = DependencyFileEvidence::default();
        for (language, delegate) in &self.delegates {
            match delegate.analyzer().dependency_file_evidence() {
                Ok(evidence) => {
                    result.rows.extend(evidence.rows);
                    result.gaps.extend(evidence.gaps);
                    result.files_read = result.files_read.saturating_add(evidence.files_read);
                    result.bytes_read = result.bytes_read.saturating_add(evidence.bytes_read);
                }
                Err(error) => result.gaps.push(DependencyEvidenceGap {
                    kind: DependencyEvidenceGapKind::Missing,
                    build_file: Default::default(),
                    byte_range: 0..0,
                    message: format!(
                        "{language:?} selected dependency publication unavailable: {error}"
                    ),
                }),
            }
        }
        result.rows.sort_by_cached_key(|row| row.id());
        // JS and TS publish the same package evidence; this is one fact.
        result.rows.dedup_by(|left, right| left.id() == right.id());
        result.gaps.sort_by(|left, right| {
            left.build_file
                .cmp(&right.build_file)
                .then_with(|| left.message.cmp(&right.message))
        });
        result.gaps.dedup();
        Ok(result)
    }

    fn source_file_inventory(&self) -> crate::analyzer::QueryBatch<ProjectFile> {
        let mut inventory = crate::analyzer::QueryBatch::complete(Vec::new(), 0);
        for delegate in self.delegates.values() {
            inventory = inventory.merge(delegate.analyzer().source_file_inventory());
        }
        inventory.rows.sort();
        inventory.rows.dedup();
        inventory
    }

    #[cfg(any(test, feature = "test-support"))]
    fn test_hooks(&self) -> &dyn crate::analyzer::AnalyzerTestHooks {
        self
    }

    fn claimed_files(&self) -> Vec<ProjectFile> {
        let mut files = self
            .delegates
            .values()
            .flat_map(|delegate| delegate.analyzer().claimed_files())
            .collect::<Vec<_>>();
        files.sort();
        files.dedup();
        files
    }

    fn workspace_declarations_with_primary_ranges(
        &self,
        cancellation: &crate::CancellationToken,
    ) -> Option<Vec<(CodeUnit, Option<Range>)>> {
        let mut declarations = Vec::new();
        for delegate in self.delegates.values() {
            declarations.extend(
                delegate
                    .analyzer()
                    .workspace_declarations_with_primary_ranges(cancellation)?,
            );
        }
        (!cancellation.is_cancelled()).then_some(declarations)
    }

    fn property_reaching_provider(
        &self,
    ) -> Option<&dyn crate::analyzer::semantic::PropertyReachingProvider> {
        Some(self)
    }

    fn invalidate_cached_file_identities(&self) {
        self.delegates
            .values()
            .for_each(|delegate| delegate.analyzer().invalidate_cached_file_identities());
    }

    fn invalidate_cached_file_identities_for(&self, changed_files: &BTreeSet<ProjectFile>) {
        self.delegates.values().for_each(|delegate| {
            delegate
                .analyzer()
                .invalidate_cached_file_identities_for(changed_files);
        });
    }

    /// Every delegate shares one `Liveness`, and so one identity scan, for the
    /// workspace: the first delegate that has taken it answers for all of them.
    fn working_tree_identity(&self) -> Option<Arc<crate::gitblob::WorkingTreeIdentity>> {
        self.delegates
            .values()
            .find_map(|delegate| delegate.analyzer().working_tree_identity())
    }

    fn begin_query(&self, context: &Arc<crate::analyzer::AnalyzerQueryContext>) {
        let mut contexts = self
            .query_contexts
            .lock()
            .expect("multi-analyzer query context mutex poisoned");
        if !contexts.iter().any(|active| Arc::ptr_eq(active, context)) {
            for active in contexts.iter() {
                if let Err(reason) = active.read_completion() {
                    context.record_read_incomplete(reason);
                }
            }
            contexts.push(Arc::clone(context));
            if context.read_ledger().is_some() {
                self.attached_read_ledgers.fetch_add(1, Ordering::Relaxed);
            }
        }
        drop(contexts);
        self.delegates
            .values()
            .for_each(|delegate| delegate.analyzer().begin_query(context));
    }

    fn end_query(&self, context: &Arc<crate::analyzer::AnalyzerQueryContext>) {
        self.delegates
            .values()
            .for_each(|delegate| delegate.analyzer().end_query(context));
        let mut contexts = self
            .query_contexts
            .lock()
            .expect("multi-analyzer query context mutex poisoned");
        let before = contexts.len();
        contexts.retain(|active| !Arc::ptr_eq(active, context));
        let retired = contexts.len() < before;
        drop(contexts);
        if retired {
            crate::analyzer::i_analyzer::decrement_attached_read_ledger(
                &self.attached_read_ledgers,
                context,
            );
        }
    }

    /// Record one input read through this facade.
    ///
    /// The delegates keep their own registries and record their own funnels;
    /// this reaches every unshadowed ledger opened against the composite so a
    /// key formed above the delegates is not lost. Forwarding to the delegates
    /// as well would only re-record the same key, which a set-valued ledger
    /// would drop anyway.
    fn record_read(&self, key: crate::analyzer::read_ledger::ReadKey) {
        if !IAnalyzer::read_ledger_attached(self) {
            return;
        }
        let contexts = self
            .query_contexts
            .lock()
            .expect("multi-analyzer query context mutex poisoned")
            .clone();
        crate::analyzer::i_analyzer::record_read_on_active_ledgers(&contexts, key);
    }

    fn record_unattributed_read(&self) {
        if !IAnalyzer::read_ledger_attached(self) {
            return;
        }
        let contexts = self
            .query_contexts
            .lock()
            .expect("multi-analyzer query context mutex poisoned")
            .clone();
        crate::analyzer::i_analyzer::record_unattributed_on_active_ledgers(&contexts);
    }

    fn read_ledger_attached(&self) -> bool {
        self.attached_read_ledgers.load(Ordering::Relaxed) > 0
    }

    fn current_thread_read_ledger(&self) -> Option<Arc<crate::analyzer::read_ledger::ReadLedger>> {
        let contexts = self
            .query_contexts
            .lock()
            .expect("multi-analyzer query context mutex poisoned");
        crate::analyzer::i_analyzer::innermost_query_context_value(&contexts, |context| {
            context.current_thread_read_ledger().cloned()
        })
    }

    fn prefetch_definitions(&self, fq_names: &[String]) {
        self.prefetch_delegates(fq_names);
    }

    fn active_query_cancellation(&self) -> Option<crate::CancellationToken> {
        self.query_contexts
            .lock()
            .expect("multi-analyzer query context mutex poisoned")
            .iter()
            .rev()
            .find_map(|context| context.cancellation().cloned())
    }

    fn active_query_semantic_model_overlay(
        &self,
    ) -> Option<Option<Arc<crate::analyzer::semantic_model::SemanticModelOverlay>>> {
        let contexts = self
            .query_contexts
            .lock()
            .expect("multi-analyzer query context mutex poisoned");
        crate::analyzer::i_analyzer::innermost_query_context_value(&contexts, |context| {
            context.semantic_model_overlay_override_for_current_thread()
        })
    }

    fn active_query_semantic_model_snapshot(
        &self,
    ) -> Option<Option<Arc<crate::analyzer::semantic_model::ActiveSemanticModelSnapshot>>> {
        let contexts = self
            .query_contexts
            .lock()
            .expect("multi-analyzer query context mutex poisoned");
        crate::analyzer::i_analyzer::innermost_query_context_value(&contexts, |context| {
            context.active_semantic_model_snapshot_override_for_current_thread()
        })
    }

    fn relational_definition_batch(
        &self,
        requests: &[RelationalDefinitionRequest],
        cancellation: &crate::CancellationToken,
    ) -> RelationalBatchOutcome {
        if cancellation.is_cancelled() {
            return RelationalBatchOutcome::Cancelled;
        }

        let mut values = requests
            .iter()
            .map(|request| RelationalDefinitionValue::empty_for(&request.query))
            .collect::<Vec<_>>();
        for (language, delegate) in &self.delegates {
            let delegated = requests
                .iter()
                .enumerate()
                .filter(|(_, request)| match request.language_scope {
                    DefinitionLanguageScope::Workspace => true,
                    DefinitionLanguageScope::Language(requested) => requested == *language,
                })
                .map(|(index, request)| {
                    let mut request = request.clone();
                    request.ordinal = index;
                    request.language_scope = DefinitionLanguageScope::Language(*language);
                    request
                })
                .collect::<Vec<_>>();
            if delegated.is_empty() {
                continue;
            }

            let results = match delegate
                .analyzer()
                .relational_definition_batch(&delegated, cancellation)
            {
                RelationalBatchOutcome::Complete(results) => results,
                RelationalBatchOutcome::Cancelled => return RelationalBatchOutcome::Cancelled,
                RelationalBatchOutcome::Failed(error) => {
                    return RelationalBatchOutcome::Failed(RelationalBatchError::new(format!(
                        "{language:?} relational definition projection failed: {}",
                        error.message()
                    )));
                }
            };
            assert_eq!(
                results.len(),
                delegated.len(),
                "a language projection returns one result per delegated request"
            );
            let mut seen = BTreeSet::new();
            for result in results {
                assert!(
                    seen.insert(result.ordinal),
                    "a language projection returned one request ordinal twice"
                );
                let value = values
                    .get_mut(result.ordinal)
                    .expect("a language projection returned an unknown request ordinal");
                value.merge_from(result.value);
            }
        }
        if cancellation.is_cancelled() {
            return RelationalBatchOutcome::Cancelled;
        }

        RelationalBatchOutcome::Complete(
            requests
                .iter()
                .zip(values)
                .map(|(request, mut value)| {
                    value.canonicalize();
                    RelationalDefinitionResult {
                        ordinal: request.ordinal,
                        value,
                    }
                })
                .collect(),
        )
    }

    /// The first delegate's cell — the same delegate `project()` answers from,
    /// so the memoized listing describes exactly the workspace this analyzer
    /// reports. `begin_query` propagates to every delegate, so it is active
    /// whenever this analyzer's own scope is.
    fn workspace_file_index_cell(&self) -> Option<crate::analyzer::WorkspaceFileIndexCell> {
        self.delegates
            .values()
            .next()?
            .analyzer()
            .workspace_file_index_cell()
    }

    /// The first delegate's memo, for the same reason as the cell above, and
    /// safely shared with lookups built directly over that delegate: every memo
    /// key names the language its answer was resolved in, and a
    /// language-scoped relational request is projected to exactly that
    /// delegate.
    fn definition_lookup_memo(
        &self,
    ) -> Option<std::sync::Arc<crate::analyzer::DefinitionLookupMemo>> {
        self.delegates
            .values()
            .next()?
            .analyzer()
            .definition_lookup_memo()
    }

    /// Recorded on this analyzer's own active contexts rather than forwarded to
    /// a delegate: `begin_query` shares one context object with every delegate,
    /// so one recording is enough, and a workspace with no delegate at all
    /// would otherwise have nowhere to report the failure.
    fn record_query_failure(&self, error: crate::analyzer::store::StoreError) {
        let contexts = self
            .query_contexts
            .lock()
            .expect("multi-analyzer query context mutex poisoned")
            .clone();
        for context in contexts {
            context.record_store_error(error.clone());
        }
    }

    fn record_query_incomplete(&self, reason: QueryReadIncomplete) {
        let contexts = self
            .query_contexts
            .lock()
            .expect("multi-analyzer query context mutex poisoned")
            .clone();
        crate::analyzer::i_analyzer::record_query_incomplete_on_active_contexts(&contexts, reason);
    }

    fn warm_query_indexes(&self) {
        self.delegates
            .values()
            .collect::<Vec<_>>()
            .into_par_iter()
            .for_each(|delegate| delegate.analyzer().warm_query_indexes());
    }

    fn query_indexes_warm(&self) -> bool {
        self.delegates
            .values()
            .all(|delegate| delegate.analyzer().query_indexes_warm())
    }

    fn external_dispatch_behavior_identity(
        &self,
    ) -> Option<crate::analyzer::semantic::StableDigest> {
        let contributions = self
            .delegates
            .iter()
            .filter_map(|(language, delegate)| {
                delegate
                    .analyzer()
                    .external_dispatch_behavior_identity()
                    .map(|identity| (*language, identity))
            })
            .collect::<Vec<_>>();
        if contributions.is_empty() {
            return None;
        }

        let mut digest = crate::analyzer::semantic::LengthDelimitedDigest::new(
            b"bifrost-multi-analyzer-external-dispatch-behavior/v1",
        );
        for (language, identity) in contributions {
            digest.push(language.config_label().as_bytes());
            digest.push(identity.as_bytes());
        }
        Some(digest.finish())
    }

    fn update(&self, changed_files: &BTreeSet<ProjectFile>) -> Self {
        let mut delegates = self.delegates.clone();
        let active_languages = self
            .build_context
            .as_ref()
            .map(|context| context.project_languages());
        let missing_languages = self
            .build_context
            .as_ref()
            .map(|context| context.changed_languages(changed_files))
            .unwrap_or_default()
            .into_iter()
            .filter(|language| !delegates.contains_key(language))
            .collect::<BTreeSet<_>>();
        for language in missing_languages.iter().copied() {
            let delegate = self
                .build_context
                .as_ref()
                .expect("missing languages require a workspace build context")
                .build_delegate(language)
                .unwrap_or_else(|error| {
                    panic!("failed to initialize {language:?} analyzer during update: {error}")
                });
            delegates.insert(language, delegate);
        }

        let updated: Vec<(Language, AnalyzerDelegate, bool)> = delegates
            .iter()
            .collect::<Vec<_>>()
            .into_par_iter()
            .map(|(language, delegate)| {
                if missing_languages.contains(language) {
                    // Construction indexed the complete current language
                    // file set, including this delta. Applying it again is
                    // redundant and can schedule avoidable store GC work.
                    return (*language, delegate.clone(), false);
                }
                let relevant: BTreeSet<ProjectFile> = changed_files
                    .iter()
                    .filter(|file| delegate.should_receive_changed_file(*language, file))
                    .cloned()
                    .collect();
                if relevant.is_empty() {
                    (*language, delegate.clone(), false)
                } else {
                    (*language, delegate.update(&relevant), true)
                }
            })
            .collect();
        let any_delegate_changed =
            !missing_languages.is_empty() || updated.iter().any(|(_, _, changed)| *changed);
        let delegates = updated
            .into_iter()
            .map(|(language, delegate, _)| (language, delegate))
            .filter(|(language, _)| {
                active_languages
                    .as_ref()
                    .is_none_or(|active| active.contains(language))
            })
            .collect::<BTreeMap<_, _>>();
        let retired_delegate = delegates.len() < self.delegates.len() + missing_languages.len();
        if any_delegate_changed || retired_delegate {
            return Self::new_with_build_context(
                delegates,
                self.derived_layer_budget_bytes,
                self.build_context.clone(),
            )
            // The derived layers and usage graphs are keyed by workspace
            // content (#2449), so a delegate change cannot make one of them
            // wrong. Carrying them across is what lets a Rust edit keep the JVM
            // usage graph and a no-op update keep everything.
            .with_snapshot_caches(self.snapshot_caches.carry_content_keyed_values_forward());
        }
        // No delegate saw a relevant change, so every one of them was cloned
        // and kept everything it had built.  Keeping the workspace-level
        // derived-layer caches too matches that, and matches what a delegate's
        // own no-op update does.  The caches are generation-guarded, so nothing
        // stale can be served through them either way.
        Self {
            delegates,
            build_context: self.build_context.clone(),
            snapshot_caches: Arc::clone(&self.snapshot_caches),
            derived_layer_budget_bytes: self.derived_layer_budget_bytes,
            query_contexts: Mutex::new(Vec::new()),
            attached_read_ledgers: AtomicUsize::new(0),
            analyzed_files_by_language: Arc::clone(&self.analyzed_files_by_language),
            resolve_definition_batch_with_source_call_count: Arc::clone(
                &self.resolve_definition_batch_with_source_call_count,
            ),
        }
    }

    fn update_all(&self) -> Self {
        self.update_all_with_progress(None)
    }

    /// A view over the delegates' own indexes, never a merged copy.
    ///
    /// Each shard is built lazily by its delegate on first use, so the cost of
    /// a definition query is exactly the per-language index the delegate would
    /// have built anyway, and it survives every update and overlay snapshot
    /// that retains the delegate.  A delegate whose store read fails degrades
    /// to its own recorded-error fallback shard, which keeps the failure
    /// visible and confined instead of emptying the whole workspace view.
    fn declaration_syntax_kind(&self, code_unit: &CodeUnit) -> Option<&'static str> {
        self.delegate_for_code_unit(code_unit)
            .and_then(|delegate| delegate.analyzer().declaration_syntax_kind(code_unit))
    }

    fn parse_errors(&self, file: &ProjectFile) -> Option<Vec<crate::analyzer::ParseError>> {
        self.delegate_for_file(file)
            .and_then(|delegate| delegate.analyzer().parse_errors(file))
    }

    fn semantic_diagnostics(
        &self,
        file: &ProjectFile,
        source: &str,
    ) -> crate::analyzer::SemanticDiagnosticReport {
        let query_scope = AnalyzerQueryScope::new(self);
        let token = query_scope.token();
        // JVM diagnostics must see the same
        // wider JVM source realm its import and hierarchy resolution do:
        // otherwise a type declared in a Java or Scala sibling file would be
        // misreported as unrecognized. Only `MultiAnalyzer` can construct
        // that realm view (see `kotlin_realm`), so this is the one place the
        // widening happens rather than inside `KotlinAnalyzer` itself.
        if language_for_file(file) == Language::Kotlin
            && self.delegates.contains_key(&Language::Kotlin)
        {
            // Every Kotlin file routes here, not only one with Java or Scala
            // peers: the realm widens *resolution*, but the active dependency
            // model that decides whether a miss is provable is published on the
            // dispatcher either way. Falling through to the delegate for a
            // Kotlin-only workspace would read its empty overlay and suppress
            // every unknown name.
            //
            // `self`, not the Kotlin delegate, for the same reason -- plus the
            // enclosing-declaration lookup, which crosses languages. The shim
            // downcasts to the Kotlin analyzer itself.
            let realm = self.kotlin_realm().map(|(_, realm)| realm);
            return crate::analyzer::kotlin::diagnostics::collect_kotlin_semantic_diagnostics(
                self,
                token,
                file,
                source,
                realm.as_ref(),
            );
        }
        if language_for_file(file) == Language::Java && self.delegates.contains_key(&Language::Java)
        {
            return crate::analyzer::java::diagnostics::collect_java_semantic_diagnostics(
                self, token, file, source,
            );
        }
        // Scala's own ladder is delegate-resident, but the active dependency
        // model it must not claim absence past is published on the dispatcher.
        if language_for_file(file) == Language::Scala
            && self.delegates.contains_key(&Language::Scala)
        {
            return crate::analyzer::scala::diagnostics::collect_scala_semantic_diagnostics(
                self, file, source,
            );
        }
        // Go classifies references that leave the workspace against the
        // activated exact API packs (#1623), and the semantic-model overlay
        // and the retained Go module graph belong to the dispatching analyzer,
        // not to the delegate. Passing `self` is what lets a Go file's import
        // of an indexed module resolve instead of reporting nothing known.
        if language_for_file(file) == Language::Go && self.delegates.contains_key(&Language::Go) {
            return crate::analyzer::go::diagnostics::collect_go_semantic_diagnostics(
                self, token, file, source,
            );
        }
        // Python's environment proof lives on the analyzer a host activated
        // packs against, which is this composite one and not the delegate. A
        // request routed straight to the delegate would see no overlay and no
        // discovery evidence, and would report every external import as an
        // unknown boundary.
        if language_for_file(file) == Language::Python
            && self.delegates.contains_key(&Language::Python)
        {
            return crate::analyzer::python::diagnostics::collect_python_semantic_diagnostics(
                self, token, file, source,
            );
        }
        // PHP's proof ladder reads the semantic-model overlay and the retained
        // Composer discovery evidence, and only the dispatching analyzer holds
        // them. Delegating to the `PhpAnalyzer` would hand the collector a view
        // with no indexed dependencies, so every vendor symbol would look
        // unknown even with an active pack.
        if language_for_file(file) == Language::Php && self.delegates.contains_key(&Language::Php) {
            return crate::analyzer::php::diagnostics::collect_php_semantic_diagnostics(
                self, file, source,
            );
        }
        // JS/TS diagnostics judge external imports against the activated npm
        // declaration surface and the retained npm discovery evidence (#1620).
        // Both hang off the analyzer that owns the workspace snapshot, which is
        // this one: a delegate passed on its own carries no snapshot caches and
        // would report every npm import as an unknown boundary.
        let language = language_for_file(file);
        if language == Language::JavaScript && self.delegates.contains_key(&Language::JavaScript) {
            return crate::analyzer::js_ts::diagnostics::collect_javascript_semantic_diagnostics(
                self, file, source,
            );
        }
        if language == Language::TypeScript && self.delegates.contains_key(&Language::TypeScript) {
            return crate::analyzer::js_ts::diagnostics::collect_typescript_semantic_diagnostics(
                self, file, source,
            );
        }
        // Rust classifies paths that leave the workspace against the activated
        // exact Cargo API packs (#1625), and the semantic-model overlay and the
        // retained Cargo dependency evidence belong to the dispatching
        // analyzer, not to the delegate. Passing `self` is what lets a path
        // into an indexed dependency resolve instead of reporting nothing
        // known.
        if language_for_file(file) == Language::Rust && self.delegates.contains_key(&Language::Rust)
        {
            return crate::analyzer::rust::diagnostics::collect_rust_semantic_diagnostics(
                self, file, source,
            );
        }
        // Ruby classifies a constant that leaves the visible require closure
        // against the activated exact gem API packs (#1624), and both the
        // semantic-model overlay and the retained Gemfile.lock discovery
        // evidence belong to the dispatching analyzer, not to the delegate.
        // Passing `self` is what lets a gem's indexed constant resolve instead
        // of reporting an unknown boundary.
        if language_for_file(file) == Language::Ruby && self.delegates.contains_key(&Language::Ruby)
        {
            return crate::analyzer::ruby::diagnostics::collect_ruby_semantic_diagnostics(
                self, file, source,
            );
        }
        // C# reads the retained dependency-discovery evidence that refines an
        // unindexed assembly boundary, and a host publishes that on the
        // analyzer it ran discovery against, which is this composite one.
        // Delegating to the `CSharpAnalyzer` would hand the collector no
        // evidence at all, so every miss past a `using` would report the
        // weakest boundary even where the build declares the assembly.
        if language_for_file(file) == Language::CSharp
            && self.delegates.contains_key(&Language::CSharp)
        {
            return crate::analyzer::csharp::diagnostics::collect_csharp_semantic_diagnostics(
                self, token, file, source,
            );
        }
        if language_for_file(file) == Language::Cpp
            && self.delegates.contains_key(&Language::Cpp)
            && let Some(cpp) =
                crate::analyzer::resolve_analyzer::<crate::analyzer::CppAnalyzer>(self)
        {
            let report =
                brokk_bifrost_cpp::diagnostics::collect_cpp_semantic_diagnostics(cpp, file, source);
            return crate::analyzer::semantic_model::degrade_pack_gap_absences(self, report);
        }
        self.delegate_for_file(file)
            .map(|delegate| delegate.analyzer().semantic_diagnostics(file, source))
            .unwrap_or_default()
    }

    fn extract_call_receiver(&self, reference: &str) -> Option<String> {
        self.delegates
            .values()
            .find_map(|delegate| delegate.analyzer().extract_call_receiver(reference))
    }

    fn import_statements(&self, file: &ProjectFile) -> Vec<String> {
        self.delegate_for_file(file)
            .map(|delegate| delegate.analyzer().import_statements(file))
            .unwrap_or_default()
    }

    fn is_access_expression(&self, file: &ProjectFile, start_byte: usize, end_byte: usize) -> bool {
        self.delegate_for_file(file)
            .map(|delegate| {
                delegate
                    .analyzer()
                    .is_access_expression(file, start_byte, end_byte)
            })
            .unwrap_or(true)
    }

    fn find_nearest_declaration(
        &self,
        file: &ProjectFile,
        start_byte: usize,
        end_byte: usize,
        ident: &str,
    ) -> Option<DeclarationInfo> {
        self.delegate_for_file(file).and_then(|delegate| {
            delegate
                .analyzer()
                .find_nearest_declaration(file, start_byte, end_byte, ident)
        })
    }

    fn compute_cognitive_complexities(&self, file: &ProjectFile) -> Vec<(CodeUnit, u32)> {
        self.delegate_for_file(file)
            .map(|delegate| delegate.analyzer().compute_cognitive_complexities(file))
            .unwrap_or_default()
    }

    fn comment_density(&self, code_unit: &CodeUnit) -> Option<CommentDensityStats> {
        self.delegate_for_code_unit(code_unit)
            .and_then(|delegate| delegate.analyzer().comment_density(code_unit))
    }

    fn comment_density_by_top_level(&self, file: &ProjectFile) -> Vec<CommentDensityStats> {
        self.delegate_for_file(file)
            .map(|delegate| delegate.analyzer().comment_density_by_top_level(file))
            .unwrap_or_default()
    }

    fn find_exception_handling_smells(
        &self,
        file: &ProjectFile,
        weights: ExceptionSmellWeights,
    ) -> ExceptionHandlingAnalysis {
        let Some(delegate) = self.delegate_for_file(file) else {
            return ExceptionHandlingAnalysis::Unsupported {
                reason: format!(
                    "no analyzer delegate is available for {}",
                    file.rel_path().display()
                ),
            };
        };
        delegate
            .analyzer()
            .find_exception_handling_smells(file, weights)
    }

    fn find_test_assertion_smells(
        &self,
        file: &ProjectFile,
        weights: TestAssertionWeights,
    ) -> Vec<TestAssertionSmell> {
        self.delegate_for_file(file)
            .map(|delegate| {
                delegate
                    .analyzer()
                    .find_test_assertion_smells(file, weights)
            })
            .unwrap_or_default()
    }

    fn find_test_assertion_smells_limited(
        &self,
        file: &ProjectFile,
        weights: TestAssertionWeights,
        max_candidates: usize,
    ) -> TestAssertionAnalysis {
        self.delegate_for_file(file)
            .map(|delegate| {
                delegate.analyzer().find_test_assertion_smells_limited(
                    file,
                    weights,
                    max_candidates,
                )
            })
            .unwrap_or(TestAssertionAnalysis {
                findings: Vec::new(),
                inspected_candidates: None,
                truncated: false,
            })
    }

    fn find_structural_clone_smells(
        &self,
        file: &ProjectFile,
        weights: CloneSmellWeights,
    ) -> Vec<CloneSmell> {
        delegate_or_default(self.delegate_for_file(file), |analyzer| {
            analyzer.find_structural_clone_smells(file, weights)
        })
    }

    fn find_structural_clone_smells_for_files(
        &self,
        files: &[ProjectFile],
        weights: CloneSmellWeights,
    ) -> Vec<CloneSmell> {
        let grouped = group_files_by_language(files, |file| self.dispatch_language(file));

        let mut findings = Vec::new();
        for (language, group) in grouped {
            if let Some(delegate) = self.delegates.get(&language) {
                findings.extend(
                    delegate
                        .analyzer()
                        .find_structural_clone_smells_for_files(&group, weights),
                );
            }
        }
        findings
    }

    fn search_symbol_candidates(
        &self,
        patterns: &SearchSymbolPatternBatch,
        cancellation: Option<&crate::CancellationToken>,
    ) -> SearchSymbolCandidates {
        self.delegates
            .values()
            .collect::<Vec<_>>()
            .into_par_iter()
            .map(|delegate| {
                delegate
                    .analyzer()
                    .search_symbol_candidates(patterns, cancellation)
            })
            .reduce(
                || SearchSymbolCandidates::complete(Vec::new(), 0),
                SearchSymbolCandidates::merge,
            )
    }

    fn canonical_code_unit(
        &self,
        unit: &CodeUnit,
        cancellation: Option<&crate::CancellationToken>,
    ) -> CodeUnit {
        self.delegate_for_code_unit(unit).map_or_else(
            || unit.clone(),
            |delegate| delegate.analyzer().canonical_code_unit(unit, cancellation),
        )
    }

    fn partial_declaration_parts(&self, code_unit: &CodeUnit) -> Option<Vec<CodeUnit>> {
        self.delegate_for_code_unit(code_unit)?
            .analyzer()
            .partial_declaration_parts(code_unit)
    }

    fn abstract_member_implementations(&self, code_unit: &CodeUnit) -> Option<Vec<CodeUnit>> {
        self.delegate_for_code_unit(code_unit)?
            .analyzer()
            .abstract_member_implementations(code_unit)
    }

    fn declaration_definition_peers(
        &self,
        file: &ProjectFile,
    ) -> Option<crate::analyzer::structural::DeclarationDefinitionPeers> {
        self.delegate_for_file(file)?
            .analyzer()
            .declaration_definition_peers(file)
    }

    fn import_analysis_provider(&self) -> Option<&dyn ImportAnalysisProvider> {
        self.delegates
            .values()
            .any(|delegate| delegate.import_analysis_provider().is_some())
            .then_some(self as &dyn ImportAnalysisProvider)
    }

    fn import_analysis_provider_for_file(
        &self,
        file: &ProjectFile,
    ) -> Option<&dyn ImportAnalysisProvider> {
        self.delegate_for_file(file)
            .and_then(AnalyzerDelegate::import_analysis_provider)
    }

    fn type_hierarchy_provider(&self) -> Option<&dyn TypeHierarchyProvider> {
        self.any_delegate(|delegate| delegate.type_hierarchy_provider().is_some())
            .then_some(self as &dyn TypeHierarchyProvider)
    }

    fn type_alias_provider(&self) -> Option<&dyn TypeAliasProvider> {
        self.any_delegate(|delegate| delegate.type_alias_provider().is_some())
            .then_some(self as &dyn TypeAliasProvider)
    }

    fn member_family_provider(&self) -> Option<&dyn crate::analyzer::usages::MemberFamilyProvider> {
        self.any_delegate(|delegate| delegate.analyzer().member_family_provider().is_some())
            .then_some(self as &dyn crate::analyzer::usages::MemberFamilyProvider)
    }

    fn python_class_hierarchy_provider_for(
        &self,
        declaration: &CodeUnit,
    ) -> Option<&dyn crate::analyzer::usages::python_class_hierarchy::PythonClassHierarchyProvider>
    {
        self.delegate_for_code_unit(declaration)
            .and_then(|delegate| {
                delegate
                    .analyzer()
                    .python_class_hierarchy_provider_for(declaration)
            })
    }

    fn test_detection_provider(&self) -> Option<&dyn TestDetectionProvider> {
        self.delegates
            .values()
            .any(|delegate| delegate.test_detection_provider().is_some())
            .then_some(self as &dyn TestDetectionProvider)
    }

    fn structural_fact_providers(
        &self,
    ) -> Vec<&dyn crate::analyzer::structural::StructuralFactProvider> {
        self.delegates
            .values()
            .flat_map(|delegate| delegate.analyzer().structural_fact_providers())
            .collect()
    }

    fn snapshot_caches(&self) -> Option<&crate::analyzer::AnalyzerSnapshotCaches> {
        if let Some(context) = self.build_context.as_ref() {
            self.snapshot_caches
                .semantic_models()
                .bind_inventory_store(context.store());
        } else if let Some(store) = self.delegates.values().find_map(|delegate| {
            delegate
                .analyzer()
                .snapshot_caches()
                .and_then(|caches| caches.semantic_models().native_inventory_store())
        }) {
            self.snapshot_caches
                .semantic_models()
                .bind_inventory_store(&store);
        }
        Some(&self.snapshot_caches)
    }

    /// One entry per delegate, or nothing at all.
    ///
    /// A delegate that cannot answer must not simply be left out: a scope
    /// digest over a subset of the languages this analyzer serves would compare
    /// equal to the same subset in a workspace that also holds the missing one,
    /// which is exactly the undersized reuse #2449 forbids. The whole answer
    /// widens instead.
    fn workspace_content_identities(
        &self,
    ) -> Option<crate::analyzer::content_identity::WorkspaceContentIdentities> {
        let mut entries = Vec::with_capacity(self.delegates.len());
        for delegate in self.delegates.values() {
            // The delegates' own per-language digests, not their folded scope
            // identities: folding twice here and once in the composite would
            // make `language(Rust)` on this analyzer differ from
            // `language(Rust)` on the delegate that answered, and a `Scope`
            // read key recorded by one could never be verified by the other.
            let identities = delegate.analyzer().workspace_content_identities()?;
            entries.extend(identities.entries().iter().copied());
        }
        Some(crate::analyzer::content_identity::WorkspaceContentIdentities::new(entries))
    }

    fn read_persisted_import_adjacency(
        &self,
        content_identity: crate::analyzer::content_identity::WorkspaceContentIdentity,
        direction: crate::analyzer::PersistedImportDirection,
        files: &[ProjectFile],
        edge_limit: usize,
    ) -> Result<Option<crate::analyzer::PersistedImportAdjacency>, crate::analyzer::store::StoreError>
    {
        match &self.build_context {
            Some(context) => {
                context.read_import_graph(content_identity, direction, files, edge_limit)
            }
            None => Ok(None),
        }
    }

    fn publish_persisted_import_graph(
        &self,
        _content_identity: crate::analyzer::content_identity::WorkspaceContentIdentity,
        _sources: &[ProjectFile],
        _edges: &[crate::analyzer::PersistedImportEdge],
    ) -> Result<bool, crate::analyzer::store::StoreError> {
        Ok(false)
    }

    fn refresh_persisted_import_graph(
        &self,
        content_identity: crate::analyzer::content_identity::WorkspaceContentIdentity,
        cancellation: Option<&crate::cancellation::CancellationToken>,
        max_files: usize,
        max_edges: usize,
    ) -> Result<
        Option<crate::analyzer::PersistedImportGraphRefresh>,
        crate::analyzer::store::StoreError,
    > {
        let diagnostics = std::env::var_os("BIFROST_IMPORT_GRAPH_REFRESH_DIAGNOSTICS")
            .is_some_and(|value| value == "1");
        let refresh_started = std::time::Instant::now();
        let Some(context) = &self.build_context else {
            return Ok(None);
        };
        if !self.workspace_content_matches(content_identity)
            || cancellation.is_some_and(crate::cancellation::CancellationToken::is_cancelled)
        {
            return Ok(None);
        }

        let mut files = self.analyzed_files();
        files.sort_by_key(crate::path_utils::rel_path_string);
        files.dedup();
        let fact_indexes = self.workspace_fact_indexes();
        let mut indexed_languages = fact_indexes
            .iter()
            .map(|index| index.fact_index_language())
            .collect::<Vec<_>>();
        indexed_languages.sort();
        indexed_languages.dedup();
        let mut workspace_languages = self.languages().into_iter().collect::<Vec<_>>();
        workspace_languages.sort();
        if indexed_languages != workspace_languages {
            return Ok(None);
        }

        let mut blobs_by_path: HashMap<String, Vec<(String, git2::Oid)>> = HashMap::default();
        for index in fact_indexes {
            let language = index.fact_index_language().config_label().to_owned();
            for (file, blob) in index.analyzed_blobs() {
                blobs_by_path
                    .entry(crate::path_utils::rel_path_string(&file))
                    .or_default()
                    .push((language.clone(), blob));
            }
        }
        let files_by_language = group_files_by_language(&files, language_for_file);
        let mut complete_dependency_paths: HashSet<String> = HashSet::default();
        let mut module_path_keys_by_path: HashMap<String, Vec<String>> = HashMap::default();
        for language_files in files_by_language.values() {
            let Some(provider) = language_files
                .first()
                .and_then(|file| self.import_analysis_provider_for_file(file))
            else {
                continue;
            };
            if !provider.has_complete_import_resolution_dependencies() {
                continue;
            }
            let Some(keys) = provider.import_graph_module_path_keys_for_files(language_files)
            else {
                continue;
            };
            assert_eq!(
                keys.len(),
                language_files.len(),
                "complete import providers return module-path keys for every source"
            );
            for (file, keys) in keys {
                let path = crate::path_utils::rel_path_string(&file);
                complete_dependency_paths.insert(path.clone());
                module_path_keys_by_path.insert(path, keys);
            }
        }
        let mut sources = Vec::with_capacity(files.len());
        for file in &files {
            let path = crate::path_utils::rel_path_string(file);
            let Some(mut blobs) = blobs_by_path.remove(&path) else {
                return Ok(None);
            };
            blobs.sort_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1)));
            let mut hasher = brokk_bifrost_core::analyzer::canonical_hash::CanonicalHasher::new(
                b"bifrost-workspace-import-source:v1",
            );
            for (language, blob) in blobs {
                hasher.field(&language, blob.as_bytes());
            }
            let module_path_keys = module_path_keys_by_path.remove(&path).unwrap_or_default();
            let complete_resolution_dependencies = complete_dependency_paths.contains(&path);
            sources.push(crate::analyzer::store::WorkspaceImportGraphSource {
                source_path: path,
                source_identity: hasher.finish(),
                module_path_keys,
                complete_resolution_dependencies,
                input_digests: None,
                binding_surface: None,
            });
        }
        if !blobs_by_path.is_empty() {
            return Ok(None);
        }

        let languages = workspace_languages
            .iter()
            .map(|language| language.config_label().to_owned())
            .collect::<Vec<_>>();
        let plan_started = std::time::Instant::now();
        let resolver_identity = context.import_graph_resolver_identity(&languages)?;
        let mut plan =
            context.plan_import_graph_refresh(content_identity, &resolver_identity, &sources)?;
        if plan.current {
            return Ok(Some(crate::analyzer::PersistedImportGraphRefresh::default()));
        }

        let input_paths = if plan.full_rebuild {
            files
                .iter()
                .map(crate::path_utils::rel_path_string)
                .collect::<HashSet<_>>()
        } else {
            plan.changed_source_paths.iter().cloned().collect()
        };
        let mut input_digest_ns = 0_u128;
        let mut input_digest_sources = 0_usize;
        for language_files in files_by_language.values() {
            let selected = language_files
                .iter()
                .filter(|file| input_paths.contains(&crate::path_utils::rel_path_string(file)))
                .cloned()
                .collect::<Vec<_>>();
            if selected.is_empty() {
                continue;
            }
            let Some(provider) = language_files
                .first()
                .and_then(|file| self.import_analysis_provider_for_file(file))
            else {
                continue;
            };
            if !provider.has_complete_import_resolution_dependencies() {
                continue;
            }
            let started = std::time::Instant::now();
            let Some(digests) =
                provider.import_graph_input_digests_for_files(&selected, cancellation)
            else {
                input_digest_ns = input_digest_ns.saturating_add(started.elapsed().as_nanos());
                continue;
            };
            input_digest_ns = input_digest_ns.saturating_add(started.elapsed().as_nanos());
            assert_eq!(
                digests.len(),
                selected.len(),
                "complete import providers return input digests for every selected source"
            );
            input_digest_sources += digests.len();
            for (file, input_digests) in digests {
                let path = crate::path_utils::rel_path_string(&file);
                let source = sources
                    .iter_mut()
                    .find(|source| source.source_path == path)
                    .expect("fingerprinted file belongs to the workspace source inventory");
                source.input_digests = Some(input_digests);
            }
        }
        let plan_ns = plan_started.elapsed().as_nanos();
        let publish_started = std::time::Instant::now();
        let identity_advanced = context.advance_import_graph_identity(
            content_identity,
            &resolver_identity,
            &plan,
            &sources,
        )?;
        let publish_ns = publish_started.elapsed().as_nanos();
        if identity_advanced {
            if diagnostics {
                eprintln!(
                    "BIFROST_IMPORT_GRAPH_REFRESH total_ns={} plan_ns={} surface_ns=0 input_digest_ns={} resolve_ns=0 publish_ns={} changed_sources={} dirty_importers={} dirty_import_ordinals={} dirty_lookup_ordinals={} input_digest_sources={} resolved_files=0 resolved_imports=0 resolved_edges=0 edge_snapshot_rows=0 dependency_delta_rows=0 dml_rows=0 full_rebuild=false identity_only=true",
                    refresh_started.elapsed().as_nanos(),
                    plan_ns,
                    input_digest_ns,
                    publish_ns,
                    plan.changed_source_paths.len(),
                    plan.dirty_importer_paths.len(),
                    plan.dirty_import_ordinals.len(),
                    plan.dirty_lookup_ordinals.len(),
                    input_digest_sources,
                );
            }
            return Ok(Some(crate::analyzer::PersistedImportGraphRefresh::default()));
        }
        let surface_paths = if plan.full_rebuild {
            files
                .iter()
                .map(crate::path_utils::rel_path_string)
                .collect::<HashSet<_>>()
        } else {
            plan.changed_source_paths.iter().cloned().collect()
        };
        let mut surface_ns = 0_u128;
        for language_files in files_by_language.values() {
            let selected = language_files
                .iter()
                .filter(|file| surface_paths.contains(&crate::path_utils::rel_path_string(file)))
                .cloned()
                .collect::<Vec<_>>();
            if selected.is_empty() {
                continue;
            }
            let Some(provider) = language_files
                .first()
                .and_then(|file| self.import_analysis_provider_for_file(file))
            else {
                continue;
            };
            if !provider.has_complete_import_resolution_dependencies() {
                continue;
            }
            let started = std::time::Instant::now();
            let Some(surfaces) =
                provider.import_graph_binding_surfaces_for_files(&selected, cancellation)
            else {
                surface_ns = surface_ns.saturating_add(started.elapsed().as_nanos());
                continue;
            };
            surface_ns = surface_ns.saturating_add(started.elapsed().as_nanos());
            assert_eq!(
                surfaces.len(),
                selected.len(),
                "complete import providers return binding surfaces for every selected source"
            );
            for (file, bindings) in surfaces {
                let path = crate::path_utils::rel_path_string(&file);
                let source = sources
                    .iter_mut()
                    .find(|source| source.source_path == path)
                    .expect("changed binding surface belongs to a workspace source");
                source.binding_surface = Some(
                    bindings
                        .into_iter()
                        .flat_map(
                            crate::analyzer::store::WorkspaceImportGraphBinding::from_provider_surface,
                        )
                        .collect(),
                );
            }
        }
        plan = context.plan_import_graph_refresh(content_identity, &resolver_identity, &sources)?;
        let plan_ns = plan_started.elapsed().as_nanos();
        if plan.full_rebuild {
            assert_eq!(
                plan.dirty_importer_paths.len(),
                files.len(),
                "a full import graph refresh resolves every analyzed source"
            );
        }
        if plan.current {
            return Ok(Some(crate::analyzer::PersistedImportGraphRefresh::default()));
        }
        let mut dirty_paths = plan
            .dirty_importer_paths
            .iter()
            .map(String::as_str)
            .collect::<HashSet<_>>();
        dirty_paths.extend(
            plan.dirty_import_ordinals
                .iter()
                .map(|(path, _)| path.as_str()),
        );
        let dirty_files = files
            .iter()
            .filter(|file| dirty_paths.contains(crate::path_utils::rel_path_string(file).as_str()))
            .cloned()
            .collect::<Vec<_>>();
        let mut selected_paths: HashMap<String, Vec<u32>> = HashMap::default();
        for (path, ordinal) in &plan.dirty_import_ordinals {
            if plan.dirty_importer_paths.binary_search(path).is_ok() {
                continue;
            }
            selected_paths
                .entry(path.clone())
                .or_default()
                .push(*ordinal);
        }
        for ordinals in selected_paths.values_mut() {
            ordinals.sort_unstable();
            ordinals.dedup();
        }
        let selected_ordinals = files
            .iter()
            .filter_map(|file| {
                selected_paths
                    .remove(&crate::path_utils::rel_path_string(file))
                    .map(|ordinals| (file.clone(), ordinals))
            })
            .collect::<HashMap<_, _>>();
        let mut graph =
            crate::analyzer::structural::derived_cache::RequestLocalDirectImportGraph::from_files(
                files.clone(),
            );
        let scope = cancellation.map_or_else(
            || AnalyzerQueryScope::new(self),
            |token| AnalyzerQueryScope::with_cancellation(self, token),
        );
        let resolve_started = std::time::Instant::now();
        let exhausted = graph.ensure_forward_selected(
            self,
            scope.token(),
            &dirty_files,
            &selected_ordinals,
            max_files,
            max_edges,
            cancellation,
        );
        let resolve_ns = resolve_started.elapsed().as_nanos();
        if exhausted
            || cancellation.is_some_and(crate::cancellation::CancellationToken::is_cancelled)
            || dirty_files
                .iter()
                .any(|file| !graph.has_cached_forward(file) || !graph.supports_source(file))
            || dirty_files.iter().any(|file| {
                let path = crate::path_utils::rel_path_string(file);
                complete_dependency_paths.contains(&path)
                    && !graph.has_resolution_dependencies(file)
            })
            || !self.workspace_content_matches(content_identity)
        {
            return Ok(None);
        }
        let edges = graph.persisted_edges();
        let dependencies = graph.persisted_resolution_dependencies();
        let publish_started = std::time::Instant::now();
        let published = context.publish_import_graph_refresh(
            content_identity,
            &resolver_identity,
            &plan,
            sources.len(),
            &sources,
            &edges,
            &dependencies,
        )?;
        let publish_ns = publish_started.elapsed().as_nanos();
        if !published {
            return Ok(None);
        }
        if diagnostics {
            eprintln!(
                "BIFROST_IMPORT_GRAPH_REFRESH total_ns={} plan_ns={} surface_ns={} input_digest_ns={} resolve_ns={} publish_ns={} changed_sources={} dirty_importers={} dirty_import_ordinals={} dirty_lookup_ordinals={} input_digest_sources={} resolved_files={} resolved_imports={} resolved_edges={} full_rebuild={} identity_only=false",
                refresh_started.elapsed().as_nanos(),
                plan_ns,
                surface_ns,
                input_digest_ns,
                resolve_ns,
                publish_ns,
                plan.changed_source_paths.len(),
                dirty_files.len(),
                plan.dirty_import_ordinals.len(),
                plan.dirty_lookup_ordinals.len(),
                input_digest_sources,
                graph.resolved_files(),
                graph.resolved_imports(),
                graph.resolved_edges(),
                plan.full_rebuild
            );
        }
        Ok(Some(crate::analyzer::PersistedImportGraphRefresh {
            recomputed_files: graph.resolved_files(),
            recomputed_imports: graph.resolved_imports(),
            recomputed_edges: graph.resolved_edges(),
        }))
    }

    /// One entry per delegate that publishes one, in delegate order.
    ///
    /// A delegate that publishes none is simply absent, which is why the
    /// caller compares this against `languages()` rather than assuming the
    /// missing language contributed nothing.
    fn workspace_fact_indexes(
        &self,
    ) -> Vec<&dyn crate::analyzer::read_verification::WorkspaceFactIndex> {
        self.delegates
            .values()
            .flat_map(|delegate| delegate.analyzer().workspace_fact_indexes())
            .collect()
    }

    fn contains_tests(&self, file: &ProjectFile) -> bool {
        self.delegate_for_file(file)
            .map(|delegate| delegate.analyzer().contains_tests(file))
            .unwrap_or(false)
    }

    fn contains_tests_for_changed_file(&self, file: &ProjectFile) -> bool {
        self.delegate_for_file(file)
            .is_some_and(|delegate| delegate.analyzer().contains_tests_for_changed_file(file))
    }

    fn in_test_region(&self, code_unit: &CodeUnit) -> bool {
        self.delegate_for_file(code_unit.source())
            .is_some_and(|delegate| delegate.analyzer().in_test_region(code_unit))
    }

    fn file_is_test_only(&self, file: &ProjectFile) -> bool {
        self.delegate_for_file(file)
            .is_some_and(|delegate| delegate.analyzer().file_is_test_only(file))
    }

    fn get_test_modules(&self, files: &[ProjectFile]) -> Vec<String> {
        let grouped = group_files_by_language(files, |file| self.dispatch_language(file));

        let mut modules = Vec::new();
        for (language, group) in grouped {
            if let Some(delegate) = self.delegates.get(&language) {
                modules.extend(delegate.analyzer().get_test_modules(&group));
            } else {
                modules.extend(IAnalyzer::get_test_modules(self, &group));
            }
        }
        modules.sort();
        modules.dedup();
        modules
    }

    fn test_files_to_code_units(&self, files: &[ProjectFile]) -> BTreeSet<CodeUnit> {
        let grouped = group_files_by_language(files, |file| self.dispatch_language(file));

        let mut result = BTreeSet::new();
        for (language, group) in grouped {
            if let Some(delegate) = self.delegates.get(&language) {
                result.extend(delegate.analyzer().test_files_to_code_units(&group));
            } else {
                result.extend(IAnalyzer::test_files_to_code_units(self, &group));
            }
        }
        result
    }
}

#[cfg(any(test, feature = "test-support"))]
impl crate::analyzer::AnalyzerTestHooks for MultiAnalyzer {
    fn arm_selector_continuation_semantic_cache_invalidation_for_test(&self) {
        self.delegate_test_hooks().for_each(|hooks| {
            hooks.arm_selector_continuation_semantic_cache_invalidation_for_test();
        });
    }

    fn invalidate_selector_continuation_semantic_cache_if_armed_for_test(&self) {
        self.delegate_test_hooks().for_each(|hooks| {
            hooks.invalidate_selector_continuation_semantic_cache_if_armed_for_test();
        });
    }

    fn selector_continuation_semantic_cache_revival_census_for_test(
        &self,
    ) -> crate::analyzer::semantic::SemanticCacheRevivalCensus {
        self.delegate_test_hooks()
            .map(|hooks| hooks.selector_continuation_semantic_cache_revival_census_for_test())
            .fold(
                crate::analyzer::semantic::SemanticCacheRevivalCensus::default(),
                crate::analyzer::semantic::SemanticCacheRevivalCensus::saturating_add,
            )
    }

    fn arm_evaluation_root_continuation_semantic_cache_invalidation_for_test(&self) {
        self.delegate_test_hooks().for_each(|hooks| {
            hooks.arm_evaluation_root_continuation_semantic_cache_invalidation_for_test();
        });
    }

    fn invalidate_evaluation_root_continuation_semantic_cache_if_armed_for_test(&self) {
        self.delegate_test_hooks().for_each(|hooks| {
            hooks.invalidate_evaluation_root_continuation_semantic_cache_if_armed_for_test();
        });
    }

    fn evaluation_root_continuation_semantic_cache_revival_census_for_test(
        &self,
    ) -> crate::analyzer::semantic::SemanticCacheRevivalCensus {
        self.delegate_test_hooks()
            .map(|hooks| {
                hooks.evaluation_root_continuation_semantic_cache_revival_census_for_test()
            })
            .fold(
                crate::analyzer::semantic::SemanticCacheRevivalCensus::default(),
                crate::analyzer::semantic::SemanticCacheRevivalCensus::saturating_add,
            )
    }

    fn semantic_materialization_census_for_test(
        &self,
    ) -> Vec<(
        crate::analyzer::semantic::WorkspaceRelativePath,
        crate::analyzer::semantic::SemanticMaterializationCensus,
    )> {
        let mut census: Vec<_> = self
            .delegate_test_hooks()
            .flat_map(|hooks| hooks.semantic_materialization_census_for_test())
            .collect();
        census.sort_by(|left, right| left.0.cmp(&right.0));
        census
    }

    fn reset_definition_candidates_query_count_for_test(&self) {
        self.delegate_test_hooks()
            .for_each(|hooks| hooks.reset_definition_candidates_query_count_for_test());
    }

    fn definition_candidates_query_count_for_test(&self) -> usize {
        self.sum_delegate_test_hook_counts(|hooks| {
            hooks.definition_candidates_query_count_for_test()
        })
    }

    fn reset_definition_prefetch_batch_count_for_test(&self) {
        self.delegate_test_hooks()
            .for_each(|hooks| hooks.reset_definition_prefetch_batch_count_for_test());
    }

    fn definition_prefetch_batch_count_for_test(&self) -> usize {
        self.sum_delegate_test_hook_counts(|hooks| hooks.definition_prefetch_batch_count_for_test())
    }

    fn reset_relational_definition_batch_call_count_for_test(&self) {
        self.delegate_test_hooks()
            .for_each(|hooks| hooks.reset_relational_definition_batch_call_count_for_test());
    }

    fn relational_definition_batch_call_count_for_test(&self) -> usize {
        self.sum_delegate_test_hook_counts(|hooks| {
            hooks.relational_definition_batch_call_count_for_test()
        })
    }

    // `resolve_definition_batch_with_source` is called with whatever
    // `&dyn IAnalyzer` its caller holds, which for a workspace is this
    // `MultiAnalyzer` itself rather than one of `delegates`. The count
    // therefore lives on this instance directly instead of being summed from
    // the delegates the way the other counters above are.
    fn record_resolve_definition_batch_with_source_call_for_test(&self) {
        crate::analyzer::i_analyzer::increment_test_hook_counter(
            &self.resolve_definition_batch_with_source_call_count,
        );
    }

    fn reset_resolve_definition_batch_with_source_call_count_for_test(&self) {
        crate::analyzer::i_analyzer::reset_test_hook_counter(
            &self.resolve_definition_batch_with_source_call_count,
        );
    }

    fn resolve_definition_batch_with_source_call_count_for_test(&self) -> usize {
        self.resolve_definition_batch_with_source_call_count
            .load(Ordering::Relaxed)
    }

    fn reset_full_declaration_scan_count_for_test(&self) {
        self.delegate_test_hooks()
            .for_each(|hooks| hooks.reset_full_declaration_scan_count_for_test());
    }

    fn full_declaration_scan_count_for_test(&self) -> usize {
        self.sum_delegate_test_hook_counts(|hooks| hooks.full_declaration_scan_count_for_test())
    }

    fn reset_candidate_hydration_count_for_test(&self) {
        self.delegate_test_hooks()
            .for_each(|hooks| hooks.reset_candidate_hydration_count_for_test());
    }

    fn candidate_hydration_count_for_test(&self) -> usize {
        self.sum_delegate_test_hook_counts(|hooks| hooks.candidate_hydration_count_for_test())
    }

    fn full_candidate_hydration_count_for_test(&self) -> usize {
        self.sum_delegate_test_hook_counts(|hooks| hooks.full_candidate_hydration_count_for_test())
    }

    fn bulk_candidate_hydration_count_for_test(&self) -> usize {
        self.sum_delegate_test_hook_counts(|hooks| hooks.bulk_candidate_hydration_count_for_test())
    }

    fn reset_java_usage_evidence_cache_stats_for_test(&self) {
        self.snapshot_caches
            .reset_java_usage_evidence_stats_for_test();
    }

    fn java_usage_evidence_cache_stats_for_test(
        &self,
    ) -> crate::analyzer::JavaUsageEvidenceCacheStats {
        self.snapshot_caches.java_usage_evidence().stats_for_test()
    }

    fn reset_workspace_path_scan_count_for_test(&self) {
        self.delegate_test_hooks()
            .for_each(|hooks| hooks.reset_workspace_path_scan_count_for_test());
    }

    fn workspace_path_scan_count_for_test(&self) -> usize {
        self.sum_delegate_test_hook_counts(|hooks| hooks.workspace_path_scan_count_for_test())
    }

    fn reset_scala_project_types_build_count_for_test(&self) {
        self.delegate_test_hooks()
            .for_each(|hooks| hooks.reset_scala_project_types_build_count_for_test());
    }

    fn scala_project_types_build_count_for_test(&self) -> usize {
        self.sum_delegate_test_hook_counts(|hooks| hooks.scala_project_types_build_count_for_test())
    }

    fn reset_scala_query_scan_counts_for_test(&self) {
        self.delegate_test_hooks()
            .for_each(|hooks| hooks.reset_scala_query_scan_counts_for_test());
    }

    fn scala_query_parse_count_for_test(&self) -> usize {
        self.sum_delegate_test_hook_counts(|hooks| hooks.scala_query_parse_count_for_test())
    }

    fn scala_query_walk_count_for_test(&self) -> usize {
        self.sum_delegate_test_hook_counts(|hooks| hooks.scala_query_walk_count_for_test())
    }

    fn reset_scala_query_file_facts_touched_for_test(&self) {
        self.delegate_test_hooks()
            .for_each(|hooks| hooks.reset_scala_query_file_facts_touched_for_test());
    }

    fn scala_query_file_facts_touched_for_test(&self) -> usize {
        self.sum_delegate_test_hook_counts(|hooks| hooks.scala_query_file_facts_touched_for_test())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::FileSetProject;
    use brokk_bifrost_core::analyzer::{RelationalDefinitionQuery, RelationalName};

    /// A two-language workspace on disk, as a `MultiAnalyzer` over real
    /// per-language delegates.  The merged definition view is only meaningful
    /// over delegates that actually hold declarations.
    fn two_language_analyzer() -> (tempfile::TempDir, MultiAnalyzer) {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(
            root.join("src/App.java"),
            "package app;\npublic class App {}\n",
        )
        .unwrap();
        std::fs::write(root.join("src/lib.rs"), "pub struct Widget;\n").unwrap();
        std::fs::write(root.join("README.md"), "docs\n").unwrap();
        let project = FileSetProject::new(
            root,
            [
                std::path::PathBuf::from("src/App.java"),
                std::path::PathBuf::from("src/lib.rs"),
                std::path::PathBuf::from("README.md"),
            ],
        );
        let delegates = BTreeMap::from([
            (
                Language::Java,
                AnalyzerDelegate::Java(JavaAnalyzer::from_project(project.clone())),
            ),
            (
                Language::Rust,
                AnalyzerDelegate::Rust(RustAnalyzer::from_project(project)),
            ),
        ]);
        (temp, MultiAnalyzer::new(delegates))
    }

    #[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
    #[test]
    fn update_with_only_irrelevant_files_retains_snapshot_caches() {
        let (_temp, analyzer) = two_language_analyzer();
        analyzer
            .test_hooks()
            .reset_full_declaration_scan_count_for_test();

        let readme = ProjectFile::new(analyzer.project().root().to_path_buf(), "README.md");
        let updated = analyzer.update(&BTreeSet::from([readme]));

        assert_eq!(
            updated.test_hooks().full_declaration_scan_count_for_test(),
            0
        );
        assert!(
            Arc::ptr_eq(&analyzer.snapshot_caches, &updated.snapshot_caches),
            "an update touching no analyzed file must keep the workspace derived-layer caches"
        );
    }

    #[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
    #[test]
    fn update_touching_an_analyzed_file_carries_the_content_keyed_caches_forward() {
        let (_temp, analyzer) = two_language_analyzer();
        let source = ProjectFile::new(analyzer.project().root().to_path_buf(), "src/App.java");
        let updated = analyzer.update(&BTreeSet::from([source]));

        // The container is new because the semantic-model publication inside it
        // is snapshot-scoped, but the two content-keyed caches ride the update
        // (#2449): a value keyed by content an edit did not touch stays exact.
        assert!(!Arc::ptr_eq(
            &analyzer.snapshot_caches,
            &updated.snapshot_caches
        ));
        assert!(std::ptr::eq(
            analyzer.snapshot_caches.derived_layers(),
            updated.snapshot_caches.derived_layers()
        ));
        assert!(std::ptr::eq(
            analyzer.snapshot_caches.usage_graphs(),
            updated.snapshot_caches.usage_graphs()
        ));
    }

    fn ecosystem_identity(
        analyzer: &MultiAnalyzer,
        ecosystem: crate::analyzer::usages::workspace_graph::UsageEcosystem,
    ) -> crate::analyzer::content_identity::WorkspaceContentIdentity {
        analyzer
            .workspace_content_identities()
            .expect("a two-language analyzer states its content identities")
            .scope(|language| {
                crate::analyzer::usages::workspace_graph::UsageEcosystem::of(language) == ecosystem
            })
            .unwrap_or_else(|| panic!("no analyzed content for {ecosystem:?}"))
    }

    fn usage_graph_key(
        analyzer: &MultiAnalyzer,
        ecosystem: crate::analyzer::usages::workspace_graph::UsageEcosystem,
    ) -> crate::analyzer::usages::workspace_graph_cache::WorkspaceUsageGraphCacheKey {
        crate::analyzer::usages::workspace_graph_cache::WorkspaceUsageGraphCacheKey::new(
            crate::analyzer::usages::workspace_graph_cache::WorkspaceUsageGraphKind::Exact,
            [ecosystem],
            ecosystem_identity(analyzer, ecosystem),
        )
    }

    fn acquire_usage_graph(
        analyzer: &MultiAnalyzer,
        ecosystem: crate::analyzer::usages::workspace_graph::UsageEcosystem,
    ) -> crate::analyzer::usages::workspace_graph_cache::WorkspaceUsageGraphCacheLifecycle {
        use crate::analyzer::usages::workspace_graph::WorkspaceUsageRankingGraph;
        use crate::analyzer::usages::workspace_graph_cache::WorkspaceUsageGraphCacheBuildOutcome;
        let acquisition = analyzer.snapshot_caches.usage_graphs().acquire(
            usage_graph_key(analyzer, ecosystem),
            &crate::cancellation::CancellationToken::default(),
            || {
                WorkspaceUsageGraphCacheBuildOutcome::Complete(WorkspaceUsageRankingGraph {
                    nodes: Vec::new(),
                    edges: Vec::new(),
                    node_indices_by_file: crate::hash::HashMap::default(),
                    resolved_ecosystems: vec![ecosystem],
                })
            },
            || true,
        );
        crate::analyzer::usages::workspace_graph_cache::ready_graph(acquisition).1
    }

    /// Milestone J (#2449) case (a): a usage graph is scoped to its ecosystems,
    /// so an edit to a language outside them must leave it reusable. Before the
    /// caches were content-keyed, the whole cache was minted fresh on every
    /// update and this graph was rebuilt for a file it does not contain.
    #[test]
    fn an_edit_to_one_language_keeps_another_ecosystems_usage_graph() {
        use crate::analyzer::usages::workspace_graph::UsageEcosystem;
        use crate::analyzer::usages::workspace_graph_cache::WorkspaceUsageGraphCacheLifecycle;

        let (_temp, analyzer) = two_language_analyzer();
        assert_eq!(
            WorkspaceUsageGraphCacheLifecycle::Built,
            acquire_usage_graph(&analyzer, UsageEcosystem::Rust)
        );
        assert_eq!(
            WorkspaceUsageGraphCacheLifecycle::Built,
            acquire_usage_graph(&analyzer, UsageEcosystem::Jvm)
        );

        let java = ProjectFile::new(analyzer.project().root().to_path_buf(), "src/App.java");
        std::fs::write(
            java.abs_path(),
            "package app;\npublic class App { void added() {} }\n",
        )
        .unwrap();
        let updated = analyzer.update(&BTreeSet::from([java]));

        assert_eq!(
            ecosystem_identity(&analyzer, UsageEcosystem::Rust),
            ecosystem_identity(&updated, UsageEcosystem::Rust),
            "a Java edit must not move the Rust content identity"
        );
        assert_ne!(
            ecosystem_identity(&analyzer, UsageEcosystem::Jvm),
            ecosystem_identity(&updated, UsageEcosystem::Jvm),
            "a Java edit must move the JVM content identity"
        );
        assert_eq!(
            WorkspaceUsageGraphCacheLifecycle::Hit,
            acquire_usage_graph(&updated, UsageEcosystem::Rust),
            "the Rust usage graph must survive an edit to a Java file"
        );
        assert_eq!(
            WorkspaceUsageGraphCacheLifecycle::Built,
            acquire_usage_graph(&updated, UsageEcosystem::Jvm),
            "the JVM usage graph must be rebuilt for the edited Java content"
        );
    }

    /// Milestone J (#2449) case (b): an update that rewrites a file with the
    /// same bytes changes no content identity, so every content-keyed cache
    /// answers from what it already holds.
    #[test]
    fn a_no_op_update_reuses_every_content_keyed_workspace_cache() {
        use crate::analyzer::structural::derived_cache::{
            DerivedLayerAcquisition, DerivedLayerBuildMetrics, DerivedLayerBuildOutcome,
            DerivedLayerRequest,
        };
        use crate::analyzer::structural::index::StructuralIndexAcquisition;
        use crate::analyzer::usages::workspace_graph::UsageEcosystem;
        use crate::analyzer::usages::workspace_graph_cache::WorkspaceUsageGraphCacheLifecycle;
        use crate::cancellation::CancellationToken;

        let (_temp, analyzer) = two_language_analyzer();
        let request = DerivedLayerRequest::complete_direct_import_topology();
        let cancellation = CancellationToken::default();

        let acquire_layer = |analyzer: &MultiAnalyzer| {
            let content = analyzer
                .workspace_content_identity()
                .expect("a two-language analyzer states a whole-workspace identity");
            let acquisition = analyzer.snapshot_caches.derived_layers().acquire(
                request,
                content,
                &cancellation,
                || DerivedLayerBuildOutcome::Unavailable {
                    reason: "the test does not need a real topology".to_string(),
                    over_budget: false,
                    rejection_scope: None,
                    metrics: DerivedLayerBuildMetrics::default(),
                },
                || true,
            );
            matches!(acquisition, DerivedLayerAcquisition::Unavailable { .. })
        };
        let structural_lifecycle = |analyzer: &MultiAnalyzer| {
            let providers = analyzer.structural_fact_providers();
            let provider = providers
                .iter()
                .find(|provider| provider.structural_language() == Language::Java)
                .expect("the Java delegate is a structural provider");
            let cache = provider
                .snapshot_structural_index_cache()
                .expect("a built-in provider owns a snapshot index cache");
            match cache.inner().acquire(*provider, &cancellation) {
                StructuralIndexAcquisition::Ready { lifecycle, .. } => lifecycle,
                other => panic!(
                    "the structural index must be acquirable: {}",
                    match other {
                        StructuralIndexAcquisition::Unavailable { reason, .. } =>
                            reason.to_string(),
                        _ => "cancelled".to_string(),
                    }
                ),
            }
        };

        assert!(acquire_layer(&analyzer));
        assert_eq!(
            WorkspaceUsageGraphCacheLifecycle::Built,
            acquire_usage_graph(&analyzer, UsageEcosystem::Jvm)
        );
        assert_eq!(
            crate::analyzer::structural::index::StructuralIndexLifecycle::Built,
            structural_lifecycle(&analyzer)
        );

        // Rewrite the same bytes: the file's blob identity is unchanged, so no
        // content identity moves even though the analyzer reconciled the file.
        let java = ProjectFile::new(analyzer.project().root().to_path_buf(), "src/App.java");
        let source = std::fs::read_to_string(java.abs_path()).unwrap();
        std::fs::write(java.abs_path(), source).unwrap();
        let updated = analyzer.update(&BTreeSet::from([java]));

        assert_eq!(
            analyzer.workspace_content_identity(),
            updated.workspace_content_identity(),
            "a no-op update must not move the workspace content identity"
        );
        assert!(acquire_layer(&updated));
        assert_eq!(
            WorkspaceUsageGraphCacheLifecycle::Hit,
            acquire_usage_graph(&updated, UsageEcosystem::Jvm)
        );
        assert_eq!(
            crate::analyzer::structural::index::StructuralIndexLifecycle::Hit,
            structural_lifecycle(&updated)
        );
        let (retained, _) = updated.snapshot_caches.usage_graphs().verdicts().totals();
        assert!(
            retained >= 1,
            "the reuse must be recorded as a retention verdict"
        );
    }

    /// Milestone J (#2449) case (c): a real content change rotates exactly the
    /// identity of the language whose content moved, and the cache records the
    /// typed rebuild verdict rather than silently missing.
    #[test]
    fn a_real_content_change_rotates_the_affected_identity() {
        use crate::analyzer::invalidation::ArtifactVerdict;

        let (_temp, analyzer) = two_language_analyzer();
        let before = analyzer
            .workspace_content_identities()
            .expect("content identities");
        assert_eq!(2, before.entries().len());

        let rust = ProjectFile::new(analyzer.project().root().to_path_buf(), "src/lib.rs");
        std::fs::write(rust.abs_path(), "pub struct Widget;\npub struct Gauge;\n").unwrap();
        let updated = analyzer.update(&BTreeSet::from([rust]));
        let after = updated
            .workspace_content_identities()
            .expect("content identities");

        assert_ne!(
            before.language(Language::Rust),
            after.language(Language::Rust)
        );
        assert_eq!(
            before.language(Language::Java),
            after.language(Language::Java)
        );
        assert_ne!(before.whole_workspace(), after.whole_workspace());

        use crate::analyzer::usages::workspace_graph::UsageEcosystem;
        acquire_usage_graph(&analyzer, UsageEcosystem::Rust);
        acquire_usage_graph(&updated, UsageEcosystem::Rust);
        let verdicts = updated.snapshot_caches.usage_graphs().verdicts().recent();
        assert!(
            verdicts.iter().any(|verdict| matches!(
                verdict,
                ArtifactVerdict::Invalidated(
                    crate::analyzer::invalidation::InvalidationReason::NoRetainedArtifact { .. }
                )
            )),
            "the rebuild after a content change must be recorded: {verdicts:?}"
        );
    }

    #[test]
    fn relational_workspace_batch_merges_language_projections() {
        let (_temp, analyzer) = two_language_analyzer();
        let root = analyzer.project().root().to_path_buf();
        let java_file = ProjectFile::new(root.clone(), "src/App.java");
        let rust_file = ProjectFile::new(root, "src/lib.rs");
        let java = analyzer
            .declarations(&java_file)
            .into_iter()
            .find(CodeUnit::is_class)
            .expect("Java class declaration");
        let rust = analyzer
            .declarations(&rust_file)
            .into_iter()
            .find(CodeUnit::is_class)
            .expect("Rust struct declaration");
        let requests = [
            RelationalDefinitionRequest {
                ordinal: 9,
                language_scope: DefinitionLanguageScope::Workspace,
                name: RelationalName::stable(java.fq().clone()),
                query: RelationalDefinitionQuery::ExactName,
            },
            RelationalDefinitionRequest {
                ordinal: 4,
                language_scope: DefinitionLanguageScope::Workspace,
                name: RelationalName::stable(rust.fq().clone()),
                query: RelationalDefinitionQuery::ExactName,
            },
        ];

        let RelationalBatchOutcome::Complete(results) =
            analyzer.relational_definition_batch(&requests, &crate::CancellationToken::new())
        else {
            panic!("mixed relational batch should complete");
        };
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].ordinal, 9);
        assert_eq!(results[1].ordinal, 4);
        assert_eq!(
            results[0].value,
            RelationalDefinitionValue::Definitions(vec![java])
        );
        assert_eq!(
            results[1].value,
            RelationalDefinitionValue::Definitions(vec![rust])
        );
    }
}
