use crate::analyzer::cpp::external::{
    CppDependencyPackAdapter, resolve_cpp_semantic_pack_dependencies,
};
use crate::analyzer::languages::language_support;
use crate::analyzer::multi_analyzer::{WorkspaceBuildContext, build_language_delegate};
use crate::analyzer::semantic_model::{
    DependencyDiscoveryEvidence, DependencyDiscoveryOutcome, DependencyPackAdapter,
    DependencyPackLimits, DependencyPackPreparationOutcome, SemanticModelActivationPersistence,
    SemanticModelActivationRequest, SemanticModelRuntimeOutcome, SemanticPackCatalog,
    acquire_active_semantic_models_with_evidence, prepare_dependency_semantic_packs,
};
use crate::analyzer::store::StoreError;
use crate::analyzer::{
    AnalyzerConfig, AnalyzerDelegate, BuildProgress, CSharpDependencyPackAdapter,
    GoDependencyPackAdapter, IAnalyzer, JsTsDependencyPackAdapter, JvmDependencyPackAdapter,
    Language, MultiAnalyzer, Project, PythonDependencyPackAdapter, RubyDependencyPackAdapter,
    RustDependencyPackAdapter, resolve_csharp_semantic_pack_dependencies,
    resolve_go_semantic_pack_dependencies, resolve_js_ts_semantic_pack_dependencies,
    resolve_jvm_semantic_pack_dependencies, resolve_python_semantic_pack_dependencies,
    resolve_ruby_semantic_pack_dependencies, resolve_rust_semantic_pack_dependencies,
};
use crate::profiling;
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::panic::AssertUnwindSafe;
use std::path::{Path, PathBuf};
use std::sync::Arc;

struct InitialBuildLock {
    _file: File,
    marker_path: PathBuf,
}

impl InitialBuildLock {
    fn acquire(db_path: &Path) -> Result<Self, StoreError> {
        let lock_path = analyzer_sidecar_path(db_path, ".initial-build.lock");
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&lock_path)
            .map_err(|error| {
                StoreError::new(format!(
                    "failed to open initial analyzer build lock {}: {error}",
                    lock_path.display()
                ))
            })?;
        file.lock().map_err(|error| {
            StoreError::new(format!(
                "failed to acquire initial analyzer build lock {}: {error}",
                lock_path.display()
            ))
        })?;
        Ok(Self {
            _file: file,
            marker_path: analyzer_sidecar_path(db_path, ".initial-build.complete"),
        })
    }

    fn publish_complete(self) -> Result<(), StoreError> {
        let parent = self.marker_path.parent().ok_or_else(|| {
            StoreError::new(format!(
                "initial analyzer build marker has no parent: {}",
                self.marker_path.display()
            ))
        })?;
        let _ = std::fs::remove_file(&self.marker_path);
        let mut marker = tempfile::NamedTempFile::new_in(parent)?;
        marker.write_all(b"complete\n")?;
        marker.as_file().sync_all()?;
        marker.persist(&self.marker_path).map_err(|error| {
            StoreError::new(format!(
                "failed to publish initial analyzer build marker {}: {}",
                self.marker_path.display(),
                error.error
            ))
        })?;
        Ok(())
    }
}

fn analyzer_sidecar_path(db_path: &Path, suffix: &str) -> PathBuf {
    let mut path = OsString::from(db_path.as_os_str());
    path.push(suffix);
    PathBuf::from(path)
}

fn initial_build_complete(
    store_context: &crate::analyzer::AnalyzerStoreContext,
    db_path: &Path,
    marker_path: &Path,
) -> Result<bool, StoreError> {
    if !marker_path.is_file() {
        return Ok(false);
    }
    store_context
        .store
        .has_published_analyzer_rows()
        .map_err(|error| {
            error.context(format!(
                "checking the persisted analyzer store at {}; this cache is derived state, so remove {} and retry to rebuild it",
                db_path.display(),
                db_path.display(),
            ))
        })
}

#[derive(Clone)]
pub struct EmptyAnalyzer {
    project: Arc<dyn Project>,
    build_context: Option<Arc<WorkspaceBuildContext>>,
}

impl EmptyAnalyzer {
    pub fn new(project: Arc<dyn Project>) -> Self {
        Self {
            project,
            build_context: None,
        }
    }

    fn new_for_workspace(build_context: Arc<WorkspaceBuildContext>) -> Self {
        Self {
            project: Arc::clone(build_context.project()),
            build_context: Some(build_context),
        }
    }

    fn clone_with_project(&self, project: Arc<dyn Project>) -> Self {
        Self {
            project: Arc::clone(&project),
            build_context: self
                .build_context
                .as_ref()
                .map(|context| Arc::new(context.clone_with_project(project))),
        }
    }
}

use crate::analyzer::CodeUnitIndex;

impl CodeUnitIndex for EmptyAnalyzer {
    fn enclosing_code_unit(
        &self,
        _file: &crate::analyzer::ProjectFile,
        _range: &crate::analyzer::Range,
    ) -> Option<crate::analyzer::CodeUnit> {
        None
    }

    fn enclosing_code_unit_for_lines(
        &self,
        _file: &crate::analyzer::ProjectFile,
        _start_line: usize,
        _end_line: usize,
    ) -> Option<crate::analyzer::CodeUnit> {
        None
    }

    fn all_declarations(&self) -> Box<dyn Iterator<Item = crate::analyzer::CodeUnit> + '_> {
        Box::new(std::iter::empty())
    }

    fn languages(&self) -> std::collections::BTreeSet<Language> {
        std::collections::BTreeSet::new()
    }

    fn project(&self) -> &dyn Project {
        self.project.as_ref()
    }

    fn get_all_declarations(&self) -> Vec<crate::analyzer::CodeUnit> {
        Vec::new()
    }

    fn declarations(
        &self,
        _file: &crate::analyzer::ProjectFile,
    ) -> std::collections::BTreeSet<crate::analyzer::CodeUnit> {
        std::collections::BTreeSet::new()
    }

    fn get_definitions(&self, _fq_name: &str) -> Vec<crate::analyzer::CodeUnit> {
        Vec::new()
    }

    fn direct_children(
        &self,
        _code_unit: &crate::analyzer::CodeUnit,
    ) -> Vec<crate::analyzer::CodeUnit> {
        Vec::new()
    }

    fn ranges(&self, _code_unit: &crate::analyzer::CodeUnit) -> Vec<crate::analyzer::Range> {
        Vec::new()
    }

    fn get_skeleton(&self, _code_unit: &crate::analyzer::CodeUnit) -> Option<String> {
        None
    }

    fn get_skeleton_header(&self, _code_unit: &crate::analyzer::CodeUnit) -> Option<String> {
        None
    }

    fn get_source(
        &self,
        _code_unit: &crate::analyzer::CodeUnit,
        _include_comments: bool,
    ) -> Option<String> {
        None
    }

    fn get_sources(
        &self,
        _code_unit: &crate::analyzer::CodeUnit,
        _include_comments: bool,
    ) -> std::collections::BTreeSet<String> {
        std::collections::BTreeSet::new()
    }

    fn search_definitions(
        &self,
        _pattern: &str,
        _auto_quote: bool,
    ) -> std::collections::BTreeSet<crate::analyzer::CodeUnit> {
        std::collections::BTreeSet::new()
    }
}

impl IAnalyzer for EmptyAnalyzer {
    fn update(
        &self,
        _changed_files: &std::collections::BTreeSet<crate::analyzer::ProjectFile>,
    ) -> Self
    where
        Self: Sized,
    {
        self.clone()
    }

    fn update_all(&self) -> Self
    where
        Self: Sized,
    {
        self.clone()
    }

    fn extract_call_receiver(&self, _reference: &str) -> Option<String> {
        None
    }

    fn import_statements(&self, _file: &crate::analyzer::ProjectFile) -> Vec<String> {
        Vec::new()
    }

    fn is_access_expression(
        &self,
        _file: &crate::analyzer::ProjectFile,
        _start_byte: usize,
        _end_byte: usize,
    ) -> bool {
        false
    }

    fn find_nearest_declaration(
        &self,
        _file: &crate::analyzer::ProjectFile,
        _start_byte: usize,
        _end_byte: usize,
        _ident: &str,
    ) -> Option<crate::analyzer::DeclarationInfo> {
        None
    }
}

#[derive(Clone)]
pub enum WorkspaceAnalyzer {
    Empty(EmptyAnalyzer),
    Multi(Box<MultiAnalyzer>),
}

/// Caller-owned state needed to activate explicitly configured dependency packs.
/// Constructing a workspace never opens a semantic-pack catalog or discovers an
/// ecosystem; hosts must opt in by supplying this context.
#[derive(Clone, Copy)]
pub struct DependencyPackWorkspaceContext<'a> {
    pub catalog: &'a SemanticPackCatalog,
    pub persistence: Option<SemanticModelActivationPersistence<'a>>,
    pub activation: &'a SemanticModelActivationRequest,
    pub limits: DependencyPackLimits,
    pub cancellation: &'a crate::CancellationToken,
}

pub type PythonSemanticModelWorkspaceContext<'a> = DependencyPackWorkspaceContext<'a>;

#[derive(Debug)]
pub struct PythonSemanticModelActivationOutcome {
    pub discovery: DependencyDiscoveryOutcome,
    pub preparation: Option<DependencyPackPreparationOutcome>,
    pub runtime: Option<SemanticModelRuntimeOutcome>,
}

/// One dependency ecosystem whose exact local evidence a host can activate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DependencyPackEcosystem {
    Jvm,
    DotNet,
    Npm,
    Python,
    Go,
    Cargo,
    Ruby,
    Composer,
    Cpp,
}

impl DependencyPackEcosystem {
    /// Every ecosystem a host can activate. Hosts iterate this to select the
    /// ecosystems their workspace needs.
    pub const ALL: [Self; 9] = [
        Self::Jvm,
        Self::DotNet,
        Self::Npm,
        Self::Python,
        Self::Go,
        Self::Cargo,
        Self::Ruby,
        Self::Composer,
        Self::Cpp,
    ];

    pub fn languages(self) -> &'static [Language] {
        match self {
            Self::Jvm => &[Language::Java, Language::Kotlin, Language::Scala],
            Self::DotNet => &[Language::CSharp],
            Self::Npm => &[Language::JavaScript, Language::TypeScript],
            Self::Python => &[Language::Python],
            Self::Go => &[Language::Go],
            Self::Cargo => &[Language::Rust],
            Self::Ruby => &[Language::Ruby],
            Self::Composer => &[Language::Php],
            Self::Cpp => &[Language::Cpp],
        }
    }

    /// Stable lowercase label used by workspace configuration documents
    /// (`.bifrost/packs.json`) and activation reporting.
    pub fn label(self) -> &'static str {
        match self {
            Self::Jvm => "jvm",
            Self::DotNet => "dotnet",
            Self::Npm => "npm",
            Self::Python => "python",
            Self::Go => "go",
            Self::Cargo => "cargo",
            Self::Ruby => "ruby",
            Self::Composer => "composer",
            Self::Cpp => "cpp",
        }
    }

    /// Parse one configuration-document label back into its ecosystem.
    pub fn from_label(label: &str) -> Option<Self> {
        Self::ALL
            .iter()
            .copied()
            .find(|ecosystem| ecosystem.label() == label)
    }

    /// Base names of the files whose change can invalidate this ecosystem's
    /// published pack proof (#1628).
    ///
    /// A host watches these names, calls
    /// [`WorkspaceAnalyzer::invalidate_dependency_pack_state`] for the matching
    /// ecosystems, and re-activates. The list covers both the files a resolver
    /// reads directly and the conventional manifests a host names as evidence
    /// for the evidence-driven ecosystems (Cargo, Ruby, Composer, Python),
    /// whose exact paths are configuration rather than convention. Naming a
    /// file that a given configuration does not read costs one redundant
    /// activation; missing one would leave stale proof in place, so this table
    /// errs toward invalidating.
    ///
    /// Reading these files is the whole of discovery: no resolver runs a
    /// package manager and none opens a network connection.
    pub fn dependency_inputs(self) -> &'static [&'static str] {
        match self {
            // `is_jvm_dependency_input` is the reader-side predicate for the
            // same inputs; these are its base names.
            Self::Jvm => &[
                "pom.xml",
                "settings.xml",
                "build.gradle",
                "build.gradle.kts",
                "settings.gradle",
                "settings.gradle.kts",
                "gradle.properties",
                "gradle.lockfile",
                "libs.versions.toml",
                "gradle-wrapper.properties",
            ],
            Self::DotNet => &["project.assets.json"],
            Self::Npm => &["package.json", "package-lock.json", "npm-shrinkwrap.json"],
            // Python discovery reads distribution metadata under the roots the
            // host configures; there is no project-level manifest it consults.
            Self::Python => &["METADATA", "RECORD", "top_level.txt"],
            Self::Go => &["go.mod", "go.sum", "go.work", "go.work.sum", "modules.txt"],
            Self::Cargo => &["Cargo.toml", "Cargo.lock"],
            Self::Ruby => &["Gemfile", "Gemfile.lock", "gems.locked"],
            Self::Composer => &["composer.json", "composer.lock", "installed.json"],
            Self::Cpp => &["compile_commands.json"],
        }
    }
}

#[derive(Debug)]
pub struct DependencyPackEcosystemOutcome {
    pub ecosystem: DependencyPackEcosystem,
    pub discovery: DependencyDiscoveryOutcome,
    pub preparation: Option<DependencyPackPreparationOutcome>,
}

/// Result of one host-owned activation transaction.
#[derive(Debug)]
pub struct DependencyPackActivationOutcome {
    pub ecosystems: Vec<DependencyPackEcosystemOutcome>,
    pub runtime: Option<SemanticModelRuntimeOutcome>,
    /// Hosts must refresh published diagnostics when this value is true.
    pub diagnostic_refresh_required: bool,
}

impl DependencyPackActivationOutcome {
    pub fn complete(&self) -> bool {
        self.ecosystems.iter().all(|outcome| {
            outcome.discovery.complete
                && outcome
                    .preparation
                    .as_ref()
                    .is_some_and(|preparation| preparation.complete)
        }) && self
            .runtime
            .as_ref()
            .is_some_and(|runtime| matches!(runtime, SemanticModelRuntimeOutcome::Ready { .. }))
    }
}

impl PythonSemanticModelActivationOutcome {
    pub fn complete(&self) -> bool {
        self.discovery.complete
            && self
                .preparation
                .as_ref()
                .is_some_and(|preparation| preparation.complete)
            && self.runtime.is_some()
    }
}

impl WorkspaceAnalyzer {
    fn from_updated_multi(analyzer: MultiAnalyzer) -> Self {
        if analyzer.delegates().is_empty()
            && let Some(build_context) = analyzer.workspace_build_context()
        {
            return Self::Empty(EmptyAnalyzer::new_for_workspace(build_context));
        }
        Self::Multi(Box::new(analyzer))
    }

    /// Discover, prepare, and publish exact local dependency packs as one
    /// analyzer-generation transaction. Diagnostic requests only read the
    /// published result and never call this host-owned method.
    pub fn activate_dependency_packs(
        &self,
        config: &AnalyzerConfig,
        ecosystems: &[DependencyPackEcosystem],
        context: DependencyPackWorkspaceContext<'_>,
    ) -> DependencyPackActivationOutcome {
        let mut outcomes = Vec::with_capacity(ecosystems.len());
        let mut activation = context.activation.clone();
        let mut publication_evidence = Vec::with_capacity(ecosystems.len());

        for ecosystem in ecosystems.iter().copied() {
            let mut limits = context.limits;
            if ecosystem == DependencyPackEcosystem::Python
                && let Some(environment) = &config.python.environment
            {
                limits.max_artifacts_per_dependency = limits
                    .max_artifacts_per_dependency
                    .max(environment.limits.max_files_per_distribution);
            }
            // Composer emits one artifact per autoload rule so a PSR-4 prefix
            // stays bound to the files it admits. Discovery caps the rule count
            // itself, so the artifact budget only has to admit that cap.
            if ecosystem == DependencyPackEcosystem::Composer {
                limits.max_artifacts_per_dependency = limits
                    .max_artifacts_per_dependency
                    .max(crate::analyzer::php::PHP_MAX_AUTOLOAD_RULES_PER_PACKAGE);
            }
            let (discovery, adapter): (DependencyDiscoveryOutcome, &dyn DependencyPackAdapter) =
                match ecosystem {
                    DependencyPackEcosystem::Jvm => (
                        resolve_jvm_semantic_pack_dependencies(
                            &config.jvm,
                            self.analyzer().project(),
                            &limits,
                            Some(context.cancellation),
                        ),
                        &JvmDependencyPackAdapter,
                    ),
                    DependencyPackEcosystem::DotNet => (
                        resolve_csharp_semantic_pack_dependencies(
                            &config.csharp,
                            self.analyzer().project(),
                            &limits,
                            Some(context.cancellation),
                        ),
                        &CSharpDependencyPackAdapter,
                    ),
                    DependencyPackEcosystem::Npm => (
                        resolve_js_ts_semantic_pack_dependencies(
                            &config.js_ts.dependency_discovery,
                            self.analyzer().project(),
                            &limits,
                            Some(context.cancellation),
                        ),
                        &JsTsDependencyPackAdapter,
                    ),
                    DependencyPackEcosystem::Python => (
                        resolve_python_semantic_pack_dependencies(
                            &config.python,
                            self.analyzer().project(),
                            &limits,
                            Some(context.cancellation),
                        ),
                        &PythonDependencyPackAdapter,
                    ),
                    DependencyPackEcosystem::Go => (
                        resolve_go_semantic_pack_dependencies(
                            &config.go,
                            self.analyzer().project(),
                            &limits,
                            Some(context.cancellation),
                        ),
                        &GoDependencyPackAdapter,
                    ),
                    DependencyPackEcosystem::Cargo => (
                        resolve_rust_semantic_pack_dependencies(
                            &config.rust,
                            self.analyzer().project(),
                            &limits,
                            Some(context.cancellation),
                        ),
                        &RustDependencyPackAdapter,
                    ),
                    DependencyPackEcosystem::Ruby => (
                        resolve_ruby_semantic_pack_dependencies(
                            &config.ruby,
                            self.analyzer().project(),
                            &limits,
                            Some(context.cancellation),
                        ),
                        &RubyDependencyPackAdapter,
                    ),
                    DependencyPackEcosystem::Composer => (
                        crate::analyzer::php::resolve_php_semantic_pack_dependencies(
                            &config.php,
                            self.analyzer().project(),
                            &limits,
                            Some(context.cancellation),
                        ),
                        &crate::analyzer::php::PhpDependencyPackAdapter,
                    ),
                    DependencyPackEcosystem::Cpp => (
                        resolve_cpp_semantic_pack_dependencies(
                            self.analyzer().project(),
                            &limits,
                            Some(context.cancellation),
                        ),
                        &CppDependencyPackAdapter,
                    ),
                };
            if discovery.cancelled || !discovery.complete {
                outcomes.push(DependencyPackEcosystemOutcome {
                    ecosystem,
                    discovery,
                    preparation: None,
                });
                return DependencyPackActivationOutcome {
                    ecosystems: outcomes,
                    runtime: None,
                    diagnostic_refresh_required: false,
                };
            }
            let preparation = prepare_dependency_semantic_packs(
                context.catalog,
                adapter,
                &discovery.dependencies,
                &limits,
                Some(context.cancellation),
            );
            if !preparation.complete {
                outcomes.push(DependencyPackEcosystemOutcome {
                    ecosystem,
                    discovery,
                    preparation: Some(preparation),
                });
                return DependencyPackActivationOutcome {
                    ecosystems: outcomes,
                    runtime: None,
                    diagnostic_refresh_required: false,
                };
            }
            activation
                .evidence
                .extend(preparation.evidence.iter().cloned());
            publication_evidence.push((
                ecosystem.languages().to_vec().into_boxed_slice(),
                DependencyDiscoveryEvidence::from_outcome(&discovery),
            ));
            outcomes.push(DependencyPackEcosystemOutcome {
                ecosystem,
                discovery,
                preparation: Some(preparation),
            });
        }

        activation.evidence.sort();
        activation.evidence.dedup();
        let runtime = acquire_active_semantic_models_with_evidence(
            self.analyzer(),
            context.catalog,
            context.persistence,
            &activation,
            Some(&publication_evidence),
            context.cancellation,
        );
        let diagnostic_refresh_required =
            matches!(runtime, SemanticModelRuntimeOutcome::Ready { .. });
        DependencyPackActivationOutcome {
            ecosystems: outcomes,
            runtime: Some(runtime),
            diagnostic_refresh_required,
        }
    }

    /// Invalidate published proof after a host observes changed dependency inputs.
    pub fn invalidate_dependency_pack_state(&self, ecosystems: &[DependencyPackEcosystem]) -> bool {
        let languages = ecosystems
            .iter()
            .flat_map(|ecosystem| ecosystem.languages().iter().copied())
            .collect::<Vec<_>>();
        self.analyzer()
            .snapshot_caches()
            .is_some_and(|caches| caches.invalidate_dependency_pack_state(&languages))
    }

    /// Discover, prepare, and publish Python environment facts into this
    /// workspace's existing snapshot. A disabled environment is a successful
    /// no-op; cancellation and unavailable preparation deliberately leave any
    /// previously published overlay unchanged.
    ///
    /// Deliberately Python-specific public workspace API, not a language
    /// capability: hosts call it by name to activate a Python interpreter's
    /// packs, and there is no other language it would dispatch over. It, along
    /// with `PythonDependencyPackAdapter` and
    /// `resolve_python_semantic_pack_dependencies`, is a named allowlist entry
    /// for the language-reach-in gate rather than a `LanguageSupport` method.
    pub fn activate_python_environment_packs(
        &self,
        config: &AnalyzerConfig,
        context: PythonSemanticModelWorkspaceContext<'_>,
    ) -> PythonSemanticModelActivationOutcome {
        let outcome =
            self.activate_dependency_packs(config, &[DependencyPackEcosystem::Python], context);
        let mut ecosystems = outcome.ecosystems.into_iter();
        let ecosystem = ecosystems
            .next()
            .expect("Python activation always records its ecosystem outcome");
        debug_assert!(ecosystems.next().is_none());
        PythonSemanticModelActivationOutcome {
            discovery: ecosystem.discovery,
            preparation: ecosystem.preparation,
            runtime: outcome.runtime,
        }
    }

    /// Retain the queryable summary of a dependency-discovery run on this
    /// analyzer, for every language the discovering ecosystem serves (Python;
    /// JavaScript and TypeScript together). Resolution-trace boundary
    /// refinement reads it to report `external_declared_unindexed` instead of
    /// `external_unknown` for names the build declares; a query never runs
    /// discovery itself.
    ///
    /// A cancelled discovery retains nothing: its outcome is a statement about
    /// the cancellation, not about the build.
    #[cfg(test)]
    pub(crate) fn retain_dependency_discovery_evidence(
        &self,
        languages: &[Language],
        discovery: &DependencyDiscoveryOutcome,
    ) {
        if discovery.cancelled {
            return;
        }
        if let Some(caches) = self.analyzer().snapshot_caches() {
            caches.retain_dependency_discovery_evidence(
                languages,
                DependencyDiscoveryEvidence::from_outcome(discovery),
            );
        }
    }

    pub fn clone_with_project(&self, project: Arc<dyn Project>) -> Self {
        match self {
            Self::Empty(analyzer) => Self::Empty(analyzer.clone_with_project(project)),
            Self::Multi(analyzer) => Self::Multi(Box::new(analyzer.clone_with_project(project))),
        }
    }

    pub fn build_ephemeral_for_languages(
        project: Arc<dyn Project>,
        config: AnalyzerConfig,
        languages: &BTreeSet<Language>,
    ) -> Result<Self, StoreError> {
        let store_context = crate::analyzer::ephemeral_store_context(project.as_ref())?;
        Self::build_filtered(project, config, Some(languages), store_context, None)
    }

    /// Build an analyzer whose store lives only in memory, no matter what the
    /// project's [`Project::persistence_root`] says.
    ///
    /// Use this for throwaway file sets — temp-directory revision exports, or a
    /// changed-file-scoped view of a live workspace — where writing an on-disk
    /// cache would be either pure waste or actively wrong (a partial file set
    /// must not become the workspace's cached picture of itself).
    pub fn build_ephemeral(
        project: Arc<dyn Project>,
        config: AnalyzerConfig,
    ) -> Result<Self, StoreError> {
        let store_context = crate::analyzer::ephemeral_store_context(project.as_ref())?;
        Self::build_filtered(project, config, None, store_context, None)
    }

    pub fn build_persisted(
        project: Arc<dyn Project>,
        config: AnalyzerConfig,
    ) -> Result<Self, StoreError> {
        Self::build_persisted_inner(project, config, None)
    }

    /// Progress-reporting variant of `build_persisted`.
    pub fn build_persisted_with_progress<F>(
        project: Arc<dyn Project>,
        config: AnalyzerConfig,
        progress: F,
    ) -> Result<Self, StoreError>
    where
        F: Fn(crate::analyzer::BuildProgressEvent) + Send + Sync + 'static,
    {
        Self::build_persisted_inner(project, config, Some(Arc::new(progress)))
    }

    fn build_persisted_inner(
        project: Arc<dyn Project>,
        config: AnalyzerConfig,
        progress: Option<BuildProgress>,
    ) -> Result<Self, StoreError> {
        let store_context = crate::analyzer::persistent_store_context(project.as_ref())?;
        let Some(db_path) = store_context.store.db_path().map(Path::to_path_buf) else {
            return Self::build_filtered(project, config, None, store_context, progress);
        };
        let marker_path = analyzer_sidecar_path(&db_path, ".initial-build.complete");
        if initial_build_complete(&store_context, &db_path, &marker_path)? {
            return Self::build_filtered(project, config, None, store_context, progress);
        }
        let lock = InitialBuildLock::acquire(&db_path)?;
        if initial_build_complete(&store_context, &db_path, &marker_path)? {
            drop(lock);
            return Self::build_filtered(project, config, None, store_context, progress);
        }
        let workspace = Self::build_filtered(project, config, None, store_context, progress)?;
        lock.publish_complete()?;
        Ok(workspace)
    }

    fn build_filtered(
        project: Arc<dyn Project>,
        config: AnalyzerConfig,
        requested_languages: Option<&BTreeSet<Language>>,
        store_context: crate::analyzer::AnalyzerStoreContext,
        progress: Option<BuildProgress>,
    ) -> Result<Self, StoreError> {
        let _scope = profiling::scope("WorkspaceAnalyzer::build");
        // A fresh abort per fan-out. The caller's context may outlive this
        // build and go on to serve lazy per-language delegate builds, and those
        // must not inherit a flag this build set.
        let store_context = crate::analyzer::AnalyzerStoreContext {
            build_abort: Arc::new(crate::analyzer::BuildAbort::default()),
            ..store_context
        };
        let mut delegates = BTreeMap::new();
        let project_languages = project.analyzer_languages();
        let selected_languages: Vec<_> = match requested_languages {
            Some(requested) if !requested.is_empty() => project_languages
                .into_iter()
                .filter(|language| requested.contains(language))
                .collect(),
            _ => project_languages.into_iter().collect(),
        };
        // One build thread per language: a single language with one pathological
        // file (a vendored million-line generated parser.c, say) otherwise
        // serializes ahead of every other language's build and dominates cold
        // start (issue #1309). Store writes stay safe because every language
        // shares the store's single writer connection behind its mutex.
        //
        // A worker panic is caught rather than unwound through the join, for two
        // reasons (issue #2359). `std::thread::scope` joins every spawned thread
        // before it returns, so unwinding out of the first join still waits for
        // the slowest sibling; catching lets the worker set the shared abort
        // first, which is what makes the siblings stop instead of running to
        // completion. And joining every handle before re-raising makes the
        // choice of which panic wins deterministic -- the first language in
        // selection order -- rather than whichever thread the join order
        // happened to reach while another was still running. The payload is
        // re-raised verbatim, so the original message and location survive.
        let mut panics: Vec<Box<dyn std::any::Any + Send>> = Vec::new();
        let built: Vec<(Language, Result<AnalyzerDelegate, StoreError>)> =
            std::thread::scope(|scope| {
                let handles: Vec<_> = selected_languages
                    .into_iter()
                    .filter(|language| *language != Language::None)
                    .map(|language| {
                        let project = Arc::clone(&project);
                        let cfg = config.clone();
                        let store_context = store_context.clone();
                        let progress = progress.as_ref().map(Arc::clone);
                        let handle = std::thread::Builder::new()
                            .name(format!("bifrost-build-{language:?}"))
                            .spawn_scoped(scope, move || {
                                let abort = Arc::clone(&store_context.build_abort);
                                let built = std::panic::catch_unwind(AssertUnwindSafe(|| {
                                    build_language_delegate(
                                        language,
                                        project,
                                        cfg,
                                        store_context,
                                        progress,
                                    )
                                }));
                                if built.is_err() {
                                    abort.abort();
                                }
                                built
                            })
                            .expect("failed to spawn language build thread");
                        (language, handle)
                    })
                    .collect();
                handles
                    .into_iter()
                    .filter_map(|(language, handle)| {
                        match handle
                            .join()
                            .unwrap_or_else(|panic| std::panic::resume_unwind(panic))
                        {
                            Ok(result) => Some((language, result)),
                            Err(payload) => {
                                panics.push(payload);
                                None
                            }
                        }
                    })
                    .collect()
            });
        if let Some(payload) = panics.into_iter().next() {
            std::panic::resume_unwind(payload);
        }
        for (language, delegate) in built {
            delegates.insert(language, delegate?);
        }

        let build_context = Arc::new(WorkspaceBuildContext::new(
            Arc::clone(&project),
            config,
            store_context,
            requested_languages.cloned(),
        ));

        Ok(if delegates.is_empty() {
            Self::Empty(EmptyAnalyzer::new_for_workspace(build_context))
        } else {
            Self::Multi(Box::new(MultiAnalyzer::new_for_workspace(
                delegates,
                build_context,
            )))
        })
    }

    pub fn analyzer(&self) -> &dyn IAnalyzer {
        match self {
            Self::Empty(analyzer) => analyzer,
            Self::Multi(analyzer) => analyzer.as_ref(),
        }
    }

    /// The on-disk path of the analyzer store this workspace persists to, or
    /// `None` when the store lives only in memory — an ephemeral build, or a
    /// persisted build whose project offers no [`Project::persistence_root`]
    /// and therefore degraded to the in-memory store.
    ///
    /// This reports what the build actually produced, not what the caller
    /// requested, so hosts that must surface their persistence decision as
    /// evidence (the extension workspace description) can read it here instead
    /// of re-deriving the cache location and guessing.
    pub fn persisted_store_path(&self) -> Option<std::path::PathBuf> {
        let build_context = match self {
            Self::Empty(analyzer) => analyzer.build_context.as_deref(),
            Self::Multi(analyzer) => analyzer.build_context(),
        };
        build_context
            .and_then(WorkspaceBuildContext::store_db_path)
            .map(std::path::Path::to_path_buf)
    }

    /// Number of files in the project, i.e. an upper bound on the distinct
    /// files any demand-cached analysis can materialize.
    ///
    /// A whole-workspace analysis such as a policy compile legitimately touches
    /// every relevant file once; the content-keyed materialization cache makes
    /// that cost proportional to distinct files, never more than this count. A
    /// caller can therefore size a materialization budget to this value instead
    /// of a fixed per-query cap that a large corpus would exceed by construction.
    /// Returns `0` when the file listing is unavailable, which callers fold into
    /// their existing lower bound with `max`.
    pub fn project_file_count(&self) -> usize {
        self.analyzer()
            .project()
            .all_files_shared()
            .map(|files| files.len())
            .unwrap_or(0)
    }

    /// Pre-build whatever lazily constructed usage indexes each language wants
    /// warmed ahead of demand. Languages that need none inherit the trait's
    /// no-op, so this stays a no-op for the workspaces they make up.
    pub fn warm_usage_analysis(&self) {
        for language in Language::ANALYZABLE {
            language_support(language)
                .expect("analyzable languages are registered")
                .warm_usage_analysis(self.analyzer());
        }
    }

    /// Bring the persisted per-file Rust usage facts up to date ahead of the
    /// first query that reads them.
    ///
    /// This replaced a workspace-wide index build (issues #1416, #1757, #1758):
    /// under usage v2 there is nothing to build, and the warm's only job is to
    /// find the live blobs analysis did not persist rows for and repair them
    /// off the request path. A no-op for workspaces without Rust.
    pub fn warm_rust_usage_facts(&self) {
        if let Some(rust) =
            crate::analyzer::resolve_analyzer::<crate::analyzer::RustAnalyzer>(self.analyzer())
        {
            // The catch-up issues per-file store queries that are only cheap
            // under request-scoped memoization; without a scope each lookup
            // re-hydrates (observed ~65s instead of ~3.5s on the Bifrost
            // workspace).
            let _scope = crate::analyzer::AnalyzerQueryScope::new(self.analyzer());
            rust.warm_usage_facts();
        }
    }

    /// Whether a Rust usage query would wait for a fact catch-up batch.
    ///
    /// Under usage v2 nothing is built, and the only wait a query can inherit
    /// is an above-threshold batch of live blobs whose facts are being
    /// persisted in the background. Answers without blocking behind that batch,
    /// which is the point (#1757). Always true for a workspace with no Rust.
    pub fn rust_usage_facts_ready(&self) -> bool {
        crate::analyzer::resolve_analyzer::<crate::analyzer::RustAnalyzer>(self.analyzer())
            .is_none_or(|rust| rust.rust_usage_facts_ready())
    }

    /// Whether the Rust fact catch-up has run for this generation. The
    /// warm-ness question, as distinct from the wait question
    /// [`Self::rust_usage_facts_ready`] answers: a session that never warms and
    /// never queries is ready but not warm.
    pub fn rust_usage_facts_warm(&self) -> bool {
        crate::analyzer::resolve_analyzer::<crate::analyzer::RustAnalyzer>(self.analyzer())
            .is_none_or(|rust| rust.rust_usage_facts_warm())
    }

    /// Select the execution-semantics provider for the requested file without
    /// widening the monolithic [`IAnalyzer`] surface.
    pub fn program_semantics_provider_for_file(
        &self,
        file: &crate::analyzer::ProjectFile,
    ) -> Option<&dyn crate::analyzer::semantic::ProgramSemanticsProvider> {
        match self {
            Self::Empty(_) => None,
            Self::Multi(analyzer) => analyzer.program_semantics_provider_for_file(file),
        }
    }

    /// Check a retained semantic handle against the complete identity of the
    /// file's current analyzer generation without rematerializing its IR.
    #[cfg(test)]
    pub(crate) fn semantic_artifact_key_is_current(
        &self,
        key: &crate::analyzer::semantic::SemanticArtifactKey,
        max_source_bytes: usize,
    ) -> Result<Option<bool>, crate::analyzer::semantic::SemanticProviderError> {
        self.semantic_artifact_key_is_current_with_source_bytes(key, max_source_bytes)
            .map(|current| current.map(|(is_current, _)| is_current))
    }

    /// Check one retained semantic identity and report the exact source bytes
    /// read so callers can enforce an aggregate validation budget.
    pub(crate) fn semantic_artifact_key_is_current_with_source_bytes(
        &self,
        key: &crate::analyzer::semantic::SemanticArtifactKey,
        max_source_bytes: usize,
    ) -> Result<Option<(bool, usize)>, crate::analyzer::semantic::SemanticProviderError> {
        let root = self.analyzer().project().root();
        if key.mount() != crate::analyzer::semantic::WorkspaceMountId::from_root(root) {
            return Ok(Some((false, 0)));
        }
        let file = crate::analyzer::ProjectFile::new(root.to_path_buf(), key.path().as_path());
        let Some(provider) = self.program_semantics_provider_for_file(&file) else {
            return Ok(Some((false, 0)));
        };
        Ok(provider
            .current_artifact_source(&file, max_source_bytes)?
            .map(|current| (current.key() == key, current.source().len())))
    }

    /// File-aware semantic materialization routed through the concrete
    /// language analyzer. Unknown extensions remain explicitly unsupported.
    pub fn materialize_program_semantics(
        &self,
        file: &crate::analyzer::ProjectFile,
        request: &mut crate::analyzer::semantic::SemanticRequest<'_>,
    ) -> Result<
        crate::analyzer::semantic::SemanticOutcome<
            Arc<crate::analyzer::semantic::SemanticArtifact>,
        >,
        crate::analyzer::semantic::SemanticProviderError,
    > {
        let Some(provider) = self.program_semantics_provider_for_file(file) else {
            return Ok(crate::analyzer::semantic::SemanticOutcome::Unsupported {
                capability: crate::analyzer::semantic::SemanticCapability::Procedures,
                partial: None,
                work: crate::analyzer::semantic::SemanticWork::default(),
            });
        };
        provider.materialize(file, request)
    }

    /// Bind the demand-materialized ICFG facade to this exact analyzer
    /// generation without widening the language analyzers or `IAnalyzer`.
    pub fn icfg_provider(&self) -> crate::analyzer::semantic::WorkspaceIcfgProvider<'_> {
        crate::analyzer::semantic::WorkspaceIcfgProvider::new(self)
    }

    /// Bind the language-neutral semantic-oracle facade to this exact analyzer
    /// generation without widening the language analyzers or `IAnalyzer`.
    pub fn semantic_oracle_provider(
        &self,
    ) -> crate::analyzer::semantic::WorkspaceSemanticOracle<'_> {
        crate::analyzer::semantic::WorkspaceSemanticOracle::new(self)
    }

    /// Which class-hierarchy expansions call dispatch may add for this
    /// workspace, as the host configured them when the workspace was built.
    ///
    /// This is the one production place the switch is read: every semantic
    /// oracle bound to this workspace inherits the answer, so a host selects
    /// the behavior once by the [`AnalyzerConfig`] it builds with instead of
    /// every call path passing a flag. A workspace assembled without a build
    /// context -- an empty analyzer, or one composed directly from delegates --
    /// keeps the default, which is every optional expansion off.
    pub fn dispatch_hierarchy_expansion(&self) -> crate::analyzer::DispatchHierarchyExpansion {
        let build_context = match self {
            Self::Empty(analyzer) => analyzer.build_context.as_deref(),
            Self::Multi(analyzer) => analyzer.build_context(),
        };
        build_context.map_or_else(
            crate::analyzer::DispatchHierarchyExpansion::default,
            |context| context.config().dispatch_hierarchy_expansion,
        )
    }

    /// Starts a request-scoped query cache across the active language analyzers.
    pub fn begin_query(&self, context: &Arc<crate::analyzer::AnalyzerQueryContext>) {
        self.analyzer().begin_query(context);
    }

    pub fn end_query(&self, context: &Arc<crate::analyzer::AnalyzerQueryContext>) {
        self.analyzer().end_query(context);
    }

    /// Build the expensive lazily-initialized per-generation query indexes
    /// ahead of demand (#1442). Idempotent; see
    /// `IAnalyzer::warm_query_indexes`.
    pub fn warm_query_indexes(&self) {
        let _scope = profiling::scope("WorkspaceAnalyzer::warm_query_indexes");
        // Index builds assume an active query read cache; without one every
        // store read misses memoization and the warm runs an order of
        // magnitude slower than the same build on the demand path. Mirror a
        // query scope (`WorkspaceQueryScope::with_context`): begin the query
        // on a clone, which shares the lazy-index cells being warmed while an
        // overlapping real query keeps its own read cache.
        let snapshot = self.clone();
        let context = Arc::new(crate::analyzer::AnalyzerQueryContext::default());
        snapshot.begin_query(&context);
        snapshot.analyzer().warm_query_indexes();
        snapshot.end_query(&context);
    }

    /// Whether every index `warm_query_indexes` would build is already built.
    pub fn query_indexes_warm(&self) -> bool {
        self.analyzer().query_indexes_warm()
    }

    pub fn update(&self, changed_files: &BTreeSet<crate::analyzer::ProjectFile>) -> Self {
        let _scope = profiling::scope("WorkspaceAnalyzer::update");
        if profiling::enabled() {
            profiling::note(format!("changed_files={}", changed_files.len()));
        }
        match self {
            Self::Empty(analyzer) => {
                let Some(build_context) = analyzer.build_context.as_ref() else {
                    return Self::Empty(analyzer.clone());
                };
                let languages = build_context.changed_languages(changed_files);
                if languages.is_empty() {
                    return Self::Empty(analyzer.clone());
                }
                let delegates = languages
                    .into_iter()
                    .map(|language| {
                        let delegate = build_context.build_delegate(language).unwrap_or_else(|error| {
                            panic!(
                                "failed to initialize {language:?} analyzer during update: {error}"
                            )
                        });
                        (language, delegate)
                    })
                    .collect();
                Self::Multi(Box::new(MultiAnalyzer::new_for_workspace(
                    delegates,
                    build_context.clone(),
                )))
            }
            Self::Multi(analyzer) => Self::from_updated_multi(analyzer.update(changed_files)),
        }
    }

    pub fn update_all(&self) -> Self {
        let _scope = profiling::scope("WorkspaceAnalyzer::update_all");
        match self {
            Self::Empty(analyzer) => {
                let Some(build_context) = analyzer.build_context.as_ref() else {
                    return Self::Empty(analyzer.clone());
                };
                let languages = build_context.project_languages();
                if languages.is_empty() {
                    return Self::Empty(analyzer.clone());
                }
                let delegates = languages
                    .into_iter()
                    .map(|language| {
                        let delegate = build_context.build_delegate(language).unwrap_or_else(|error| {
                            panic!(
                                "failed to initialize {language:?} analyzer during full update: {error}"
                            )
                        });
                        (language, delegate)
                    })
                    .collect();
                Self::Multi(Box::new(MultiAnalyzer::new_for_workspace(
                    delegates,
                    build_context.clone(),
                )))
            }
            Self::Multi(analyzer) => Self::from_updated_multi(analyzer.update_all()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::{OverlayProject, ProjectFile, TestProject};
    use crate::gitblob::test_repo::{commit_all, init_repo};
    use rusqlite::Connection;

    #[test]
    fn semantic_generation_check_rejects_a_stale_configuration_identity() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let file = ProjectFile::new(root.clone(), "src/generation.ts");
        file.write("export const generation = 1;\n").unwrap();
        let project: Arc<dyn Project> = Arc::new(TestProject::new(root, Language::TypeScript));
        let workspace = WorkspaceAnalyzer::build_ephemeral(project, AnalyzerConfig::default())
            .expect("ephemeral workspace should build");
        let cancellation = crate::analyzer::semantic::CancellationToken::default();
        let mut budget = crate::analyzer::semantic::SemanticBudget::default();
        let artifact = workspace
            .materialize_program_semantics(
                &file,
                &mut crate::analyzer::semantic::SemanticRequest::new(&mut budget, &cancellation),
            )
            .unwrap()
            .available_value()
            .cloned()
            .expect("semantic artifact");
        assert!(
            workspace
                .semantic_artifact_key_is_current(artifact.key(), usize::MAX)
                .unwrap()
                .expect("source within limit")
        );

        let current = artifact.key();
        let stale = crate::analyzer::semantic::SemanticArtifactKey::new(
            current.mount(),
            current.path().clone(),
            current.language(),
            current.revision(),
            current.adapter().clone(),
            current.ir_version(),
            crate::analyzer::semantic::ConfigurationFingerprint::hash_bytes(b"stale-configuration"),
            current.dependencies(),
        );
        assert_eq!(
            workspace
                .semantic_artifact_key_is_current(&stale, usize::MAX)
                .unwrap(),
            Some(false)
        );
    }

    #[test]
    fn warm_query_indexes_reaches_language_analyzers_through_every_workspace_shape() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        ProjectFile::new(root.clone(), "src/lib.rs")
            .write("trait Runnable {}\npub struct Worker;\nimpl Runnable for Worker {}\n")
            .unwrap();

        let single: Arc<dyn Project> = Arc::new(TestProject::new(root.clone(), Language::Rust));
        let single = WorkspaceAnalyzer::build_ephemeral(single, AnalyzerConfig::default())
            .expect("ephemeral workspace should build");
        assert!(!single.query_indexes_warm());
        single.warm_query_indexes();
        assert!(single.query_indexes_warm());

        let multi: Arc<dyn Project> = Arc::new(TestProject::with_languages(
            root,
            BTreeSet::from([Language::Rust, Language::Java]),
        ));
        let multi = WorkspaceAnalyzer::build_ephemeral(multi, AnalyzerConfig::default())
            .expect("ephemeral workspace should build");
        assert!(!multi.query_indexes_warm());
        multi.warm_query_indexes();
        assert!(multi.query_indexes_warm());
    }

    /// The two Rust usage predicates a caller can ask a workspace, and the
    /// distinction ExecPlan Milestone 3 introduced between them: readiness is
    /// "would a query wait", which a healthy workspace answers `true` even
    /// before any warm because v2 has nothing to build, and warmth is "has the
    /// catch-up run for this generation", which only the warm makes true.
    /// Neither may be `false` for a workspace with no Rust.
    #[test]
    fn rust_usage_readiness_and_warmth_are_distinct_and_vacuous_without_rust() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        ProjectFile::new(root.clone(), "src/lib.rs")
            .write("pub mod worker;\npub fn root() {}\n")
            .unwrap();
        ProjectFile::new(root.clone(), "src/worker.rs")
            .write("use crate::root;\npub fn run() { root(); }\n")
            .unwrap();

        let rust: Arc<dyn Project> = Arc::new(TestProject::new(root.clone(), Language::Rust));
        let rust = WorkspaceAnalyzer::build_ephemeral(rust, AnalyzerConfig::default())
            .expect("ephemeral workspace should build");
        assert!(rust.rust_usage_facts_ready());
        assert!(!rust.rust_usage_facts_warm());
        rust.warm_rust_usage_facts();
        assert!(rust.rust_usage_facts_ready());
        assert!(rust.rust_usage_facts_warm());

        let java: Arc<dyn Project> = Arc::new(TestProject::new(root, Language::Java));
        let java = WorkspaceAnalyzer::build_ephemeral(java, AnalyzerConfig::default())
            .expect("ephemeral workspace should build");
        assert!(java.rust_usage_facts_ready());
        assert!(java.rust_usage_facts_warm());
    }

    #[test]
    fn unsupported_analyzer_query_remains_a_healthy_empty_result() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let project: Arc<dyn Project> = Arc::new(TestProject::new(root, Language::Python));
        let analyzer = EmptyAnalyzer::new(project);
        let context = Arc::new(crate::analyzer::AnalyzerQueryContext::default());

        analyzer.begin_query(&context);
        assert!(analyzer.definitions("Missing").next().is_none());
        assert!(context.store_error().is_none());
        analyzer.end_query(&context);
    }

    #[test]
    fn multi_workspace_derived_cache_uses_configured_budget_share() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let project: Arc<dyn Project> = Arc::new(TestProject::with_languages(
            root,
            BTreeSet::from([Language::Java, Language::TypeScript]),
        ));
        let config = AnalyzerConfig {
            memo_cache_budget_bytes: Some(1024 * 1024),
            ..AnalyzerConfig::default()
        };
        let workspace = WorkspaceAnalyzer::build_ephemeral(Arc::clone(&project), config)
            .expect("ephemeral workspace should build");
        assert_eq!(
            workspace
                .analyzer()
                .snapshot_caches()
                .expect("multi workspace caches")
                .derived_layers()
                .max_retained_bytes(),
            128 * 1024
        );

        let overlay = Arc::new(OverlayProject::new(project));
        let snapshot = workspace.clone_with_project(overlay as Arc<dyn Project>);
        assert_eq!(
            snapshot
                .analyzer()
                .snapshot_caches()
                .expect("snapshot caches")
                .derived_layers()
                .max_retained_bytes(),
            128 * 1024
        );
    }

    #[test]
    fn request_overlay_snapshot_cannot_replace_committed_structural_facts() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let disk_source = "export const disk = call(1);\n";
        let overlay_source = "export const overlay = call(1, 2);\nexport const extra = call(3);\n";
        std::fs::write(root.join(".gitignore"), ".bifrost/cache/\n").unwrap();
        std::fs::write(root.join("app.ts"), disk_source).unwrap();
        let repository = init_repo(&root);
        commit_all(&repository, "disk source");
        let project: Arc<dyn Project> =
            Arc::new(TestProject::new(root.clone(), Language::TypeScript));
        let file = ProjectFile::new(root.clone(), "app.ts");

        let disk_workspace =
            WorkspaceAnalyzer::build_persisted(Arc::clone(&project), AnalyzerConfig::default())
                .expect("persisted analyzer should build");
        let disk_provider = disk_workspace.analyzer().structural_search_providers()[0];
        let disk_facts = disk_provider.structural_facts(&file).unwrap();
        let disk_fact_count = disk_facts.nodes().len();
        assert_eq!(disk_facts.source(), disk_source);

        let overlay = Arc::new(OverlayProject::new(Arc::clone(&project)));
        assert!(overlay.set(file.abs_path(), overlay_source.to_owned()));
        let overlay_workspace =
            disk_workspace.clone_with_project(Arc::clone(&overlay) as Arc<dyn Project>);
        let overlay_provider = overlay_workspace.analyzer().structural_search_providers()[0];
        let extractions_before = overlay_provider.structural_extraction_count();
        let overlay_facts = overlay_provider.structural_facts(&file).unwrap();
        assert_eq!(overlay_facts.source(), overlay_source);
        assert_ne!(overlay_facts.nodes().len(), disk_fact_count);
        assert_eq!(
            overlay_provider.structural_extraction_count(),
            extractions_before + 1,
            "the unseen overlay blob must extract its own facts"
        );
        drop(overlay_workspace);
        drop(disk_workspace);

        let disk_reopened = WorkspaceAnalyzer::build_persisted(project, AnalyzerConfig::default())
            .expect("persisted analyzer should reopen");
        let disk_provider = disk_reopened.analyzer().structural_search_providers()[0];
        let hydrated_before = disk_provider.structural_hydration_count();
        let disk_facts = disk_provider.structural_facts(&file).unwrap();
        assert_eq!(disk_facts.source(), disk_source);
        assert_eq!(disk_facts.nodes().len(), disk_fact_count);
        assert_eq!(disk_provider.structural_extraction_count(), 0);
        assert_eq!(
            disk_provider.structural_hydration_count(),
            hydrated_before + 1
        );
        drop(disk_reopened);

        let disk_oid = git2::Oid::hash_object(git2::ObjectType::Blob, disk_source.as_bytes())
            .expect("hash committed source");
        let committed_snapshot_rows = Connection::open(
            root.join(".bifrost/cache")
                .join(crate::cache_db::cache_db_file_name()),
        )
        .unwrap()
        .query_row(
            "SELECT COUNT(*) FROM structural_facts_snapshots
                 WHERE blob_oid = ?1 AND lang = 'typescript:ts'",
            [disk_oid.to_string()],
            |row| row.get::<_, usize>(0),
        )
        .unwrap();
        assert_eq!(
            committed_snapshot_rows, 1,
            "overlay analysis must not replace the committed source snapshot"
        );
    }
}
