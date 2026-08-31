use crate::analyzer::cpp::external::{
    CppDependencyPackAdapter, resolve_cpp_semantic_pack_dependencies,
};
use crate::analyzer::languages::language_support;
use crate::analyzer::multi_analyzer::{WorkspaceBuildContext, build_language_delegate};
use crate::analyzer::semantic_model::{
    DependencyDiscoveryEvidence, DependencyDiscoveryOutcome, DependencyPackAdapter,
    DependencyPackLimits, DependencyPackPreparationOutcome, DependencyResolver,
    DependencyResolverBounds, SemanticModelActivationPersistence, SemanticModelActivationRequest,
    SemanticModelRuntimeOutcome, SemanticPackCatalog, SubprocessPolicy,
    acquire_active_semantic_models_with_evidence, prepare_compatible_installed_semantic_packs,
    prepare_dependency_semantic_packs,
};
use crate::analyzer::store::StoreError;
use crate::analyzer::tree_sitter_analyzer::WorkspaceBuildSnapshot;
use crate::analyzer::{
    AnalyzerBuildTierAccess, AnalyzerConfig, AnalyzerDelegate, BuildProgress,
    CSharpDependencyPackAdapter, GoDependencyDiscoveryMode, GoDependencyPackAdapter, IAnalyzer,
    JsTsDependencyPackAdapter, JvmDependencyDiscoveryMode, JvmDependencyPackAdapter, Language,
    MultiAnalyzer, Project, PythonDependencyPackAdapter, RevisionBlobIdentities,
    RubyDependencyPackAdapter, RustDependencyPackAdapter,
    resolve_csharp_semantic_pack_dependencies, resolve_go_semantic_pack_dependencies,
    resolve_js_ts_semantic_pack_dependencies, resolve_jvm_semantic_pack_dependencies,
    resolve_python_semantic_pack_dependencies, resolve_ruby_semantic_pack_dependencies,
    resolve_rust_semantic_pack_dependencies,
};
use crate::profiling;
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::panic::AssertUnwindSafe;
use std::path::{Path, PathBuf};
use std::sync::Arc;

struct WorkspaceBuildLock {
    _file: File,
}

impl WorkspaceBuildLock {
    fn acquire(db_path: &Path) -> Result<Self, StoreError> {
        // Keep the established sidecar name so processes running older Bifrost
        // builds coordinate on the same OS lock during an upgrade.
        let lock_path = analyzer_sidecar_path(db_path, ".initial-build.lock");
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&lock_path)
            .map_err(|error| {
                StoreError::new(format!(
                    "failed to open workspace analyzer build lock {}: {error}",
                    lock_path.display()
                ))
            })?;
        let _scope = profiling::scope("WorkspaceAnalyzer::build_lock_wait");
        file.lock().map_err(|error| {
            StoreError::new(format!(
                "failed to acquire workspace analyzer build lock {}: {error}",
                lock_path.display()
            ))
        })?;
        Ok(Self { _file: file })
    }
}

fn analyzer_sidecar_path(db_path: &Path, suffix: &str) -> PathBuf {
    let mut path = OsString::from(db_path.as_os_str());
    path.push(suffix);
    PathBuf::from(path)
}

/// The repository's shared content-addressed analyzer cache, opened once for a
/// request that analyzes immutable revisions of that repository.
///
/// Parsed facts are keyed by Git blob id and language storage key, not by
/// workspace, so a revision image can read every blob the cache already holds
/// -- from the live worktree, a linked worktree, or an earlier revision
/// request -- and contributes the ones it had to parse back to all of them.
/// The cache location resolves from the *original* repository root through the
/// standard funnel; a revision image's own root is a self-deleting export
/// directory and must never be used to derive it.
pub(crate) struct SharedAnalyzerCache {
    store: Arc<crate::analyzer::store::AnalyzerStore>,
}

impl SharedAnalyzerCache {
    /// Open the persisted cache serving `repository_root`.
    ///
    /// Opening is strict. A request that analyzes an immutable revision reads
    /// and writes this cache, and a host that cannot open it has no silently
    /// equivalent slower path: an ephemeral rebuild re-parses every blob of
    /// every revision on every request, so it is a performance failure worth
    /// reporting rather than absorbing. Two things fail here. `repository_root`
    /// may not be in a Git repository, which no immutable request reaches in
    /// practice because resolving the revision already needed one -- a bare
    /// repository passes, because reading a revision needs the object database
    /// and not a checkout; or the store
    /// may refuse the cache -- an unwritable or read-only checkout, or a
    /// filesystem SQLite rejects. The escape for a checkout that must stay
    /// read-only is `BIFROST_CACHE_ROOT`, which relocates the cache off the
    /// repository.
    pub(crate) fn open(repository_root: &Path) -> Result<Self, StoreError> {
        if !brokk_bifrost_core::gitblob::has_object_database(repository_root) {
            return Err(StoreError::new(format!(
                "{} is not inside a git repository, so it has no shared analyzer cache to serve immutable revision analysis",
                repository_root.display()
            )));
        }
        let db_path = crate::analyzer::store::analyzer_db_path(repository_root);
        let store = crate::analyzer::store::AnalyzerStore::open_persistent(&db_path).map_err(
            |error| {
                error.context(format!(
                    "opening the shared analyzer cache at {} for immutable revision analysis; this cache is derived state, so remove {} and retry to rebuild it, or set BIFROST_CACHE_ROOT to relocate it off a read-only checkout",
                    db_path.display(),
                    db_path.display(),
                ))
            },
        )?;
        Ok(Self {
            store: Arc::new(store),
        })
    }

    fn store(&self) -> Arc<crate::analyzer::store::AnalyzerStore> {
        Arc::clone(&self.store)
    }

    /// Claim the workspace projection rows an immutable image at `image_root`
    /// is about to publish, so they are removed when the request ends.
    pub(crate) fn claim_revision_workspace(
        &self,
        image_root: &Path,
    ) -> RevisionWorkspaceProjection {
        RevisionWorkspaceProjection {
            store: self.store(),
            // Resolved now, while the export directory still exists:
            // `WorkspaceId::for_root` canonicalizes, and a canonicalization
            // that fails after the directory is unlinked would produce a
            // different identity than the build published under.
            workspace_id: crate::analyzer::store::WorkspaceId::for_root(image_root),
        }
    }
}

/// The workspace projection rows one immutable revision image publishes into a
/// shared cache, removed when this value drops.
///
/// Query paths mount a workspace's files through `workspace_heads` and
/// `workspace_file_versions`, so a revision image must publish them to be
/// queryable at all -- declaration lookup, package resolution and path-symbol
/// resolution all read those rows. They describe a temp-directory root that
/// stops existing when the request ends, though, so leaving them behind would
/// grow the shared cache by one whole file listing per request forever. The
/// parsed blob facts the same build published are keyed by content and stay:
/// those are the reusable asset.
pub(crate) struct RevisionWorkspaceProjection {
    store: Arc<crate::analyzer::store::AnalyzerStore>,
    workspace_id: crate::analyzer::store::WorkspaceId,
}

impl Drop for RevisionWorkspaceProjection {
    fn drop(&mut self) {
        if let Err(error) = self.store.delete_workspace_projection(&self.workspace_id) {
            eprintln!(
                "bifrost: could not drop the revision image's workspace projection rows from the \
                 shared analyzer cache; they will be reclaimed when this language's analysis \
                 generation next changes: {error}"
            );
        }
    }
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
    /// Most of discovery is reading these files. Two ecosystems can do more
    /// than read: JVM discovery in `JvmDependencyDiscoveryMode::OfflineBuildTools`
    /// runs Maven and Gradle, and Go discovery runs `go list`. Each resolver
    /// states which through [`DependencyResolver::bounds`], because this
    /// sentence used to claim no resolver ran a package manager and was wrong
    /// for exactly those two (#2442).
    pub fn dependency_inputs(self) -> &'static [&'static str] {
        self.resolver().dependency_inputs()
    }

    /// Whether a revision path must accompany this ecosystem's source files
    /// in an immutable file-dependency image.
    ///
    /// This is the reader-side predicate, not merely the manifest basename
    /// list used for dependency-pack invalidation. JVM and .NET analyzers also
    /// consume patterned build inputs such as arbitrary `*.gradle`, `*.props`,
    /// and `*.targets` files. Keeping the predicate here gives workspace
    /// construction and revision export one source of truth.
    pub(crate) fn is_file_dependency_input(self, path: &Path) -> bool {
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("");
        match self {
            Self::Jvm => {
                crate::analyzer::jvm::dependency_discovery::is_jvm_dependency_input_path(path)
            }
            Self::DotNet => crate::analyzer::csharp::is_csharp_dependency_input_path(path),
            Self::Npm => {
                self.dependency_inputs().contains(&name)
                    || matches!(name, "tsconfig.json" | "jsconfig.json")
            }
            Self::Cpp => path == Path::new("compile_commands.json"),
            Self::Python | Self::Go | Self::Cargo | Self::Ruby | Self::Composer => {
                self.dependency_inputs().contains(&name)
            }
        }
    }

    /// The resolver that discovers this ecosystem's dependencies, paired with
    /// the adapter that turns them into packs.
    ///
    /// This registry replaced a hard-coded match in
    /// [`WorkspaceAnalyzer::activate_dependency_packs`] that restated the
    /// resolver-to-adapter pairing inline, which is how the activation loop
    /// came to hold per-ecosystem limit adjustments as well.
    pub(crate) fn resolver(self) -> &'static dyn DependencyResolver {
        match self {
            Self::Jvm => &JvmDependencyResolver,
            Self::DotNet => &DotNetDependencyResolver,
            Self::Npm => &NpmDependencyResolver,
            Self::Python => &PythonDependencyResolver,
            Self::Go => &GoDependencyResolver,
            Self::Cargo => &CargoDependencyResolver,
            Self::Ruby => &RubyDependencyResolver,
            Self::Composer => &ComposerDependencyResolver,
            Self::Cpp => &CppDependencyResolver,
        }
    }
}

/// The bounds a resolver that only reads files declares: no process, no clock
/// of its own, and a walk bounded by the project's file listing and
/// `DependencyPackLimits`.
const READS_FILES_ONLY: DependencyResolverBounds = DependencyResolverBounds {
    max_files_walked: None,
    max_metadata_bytes: None,
    subprocess: SubprocessPolicy::Forbidden,
    wall_clock: None,
};

struct JvmDependencyResolver;

impl DependencyResolver for JvmDependencyResolver {
    fn adapter(&self) -> &'static dyn DependencyPackAdapter {
        &JvmDependencyPackAdapter
    }

    fn dependency_inputs(&self) -> &'static [&'static str] {
        // `is_jvm_dependency_input` is the reader-side predicate for the same
        // inputs; these are its base names.
        &[
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
        ]
    }

    fn bounds(&self, config: &AnalyzerConfig) -> DependencyResolverBounds {
        let discovery = &config.jvm.dependency_discovery;
        let runs_tools = discovery.mode == JvmDependencyDiscoveryMode::OfflineBuildTools;
        DependencyResolverBounds {
            max_files_walked: None,
            max_metadata_bytes: Some(crate::analyzer::jvm::MAX_BUILD_METADATA_BYTES as u64),
            subprocess: if runs_tools {
                SubprocessPolicy::OfflineBuildTools
            } else {
                SubprocessPolicy::Forbidden
            },
            wall_clock: runs_tools.then_some(discovery.timeout),
        }
    }

    fn resolve(
        &self,
        config: &AnalyzerConfig,
        project: &dyn Project,
        limits: &DependencyPackLimits,
        cancellation: Option<&crate::CancellationToken>,
    ) -> DependencyDiscoveryOutcome {
        resolve_jvm_semantic_pack_dependencies(&config.jvm, project, limits, cancellation)
    }
}

struct DotNetDependencyResolver;

impl DependencyResolver for DotNetDependencyResolver {
    fn adapter(&self) -> &'static dyn DependencyPackAdapter {
        &CSharpDependencyPackAdapter
    }

    fn dependency_inputs(&self) -> &'static [&'static str] {
        &["project.assets.json"]
    }

    fn bounds(&self, _config: &AnalyzerConfig) -> DependencyResolverBounds {
        READS_FILES_ONLY
    }

    fn resolve(
        &self,
        config: &AnalyzerConfig,
        project: &dyn Project,
        limits: &DependencyPackLimits,
        cancellation: Option<&crate::CancellationToken>,
    ) -> DependencyDiscoveryOutcome {
        resolve_csharp_semantic_pack_dependencies(&config.csharp, project, limits, cancellation)
    }
}

struct NpmDependencyResolver;

impl DependencyResolver for NpmDependencyResolver {
    fn adapter(&self) -> &'static dyn DependencyPackAdapter {
        &JsTsDependencyPackAdapter
    }

    fn dependency_inputs(&self) -> &'static [&'static str] {
        &["package.json", "package-lock.json", "npm-shrinkwrap.json"]
    }

    fn bounds(&self, _config: &AnalyzerConfig) -> DependencyResolverBounds {
        READS_FILES_ONLY
    }

    fn resolve(
        &self,
        config: &AnalyzerConfig,
        project: &dyn Project,
        limits: &DependencyPackLimits,
        cancellation: Option<&crate::CancellationToken>,
    ) -> DependencyDiscoveryOutcome {
        resolve_js_ts_semantic_pack_dependencies(
            &config.js_ts.dependency_discovery,
            project,
            limits,
            cancellation,
        )
    }
}

struct PythonDependencyResolver;

impl DependencyResolver for PythonDependencyResolver {
    fn adapter(&self) -> &'static dyn DependencyPackAdapter {
        &PythonDependencyPackAdapter
    }

    fn dependency_inputs(&self) -> &'static [&'static str] {
        // Python discovery reads distribution metadata under the roots the
        // host configures, plus the workspace's own toolchain declaration
        // files, which key the standard-library pack selection (#1869).
        &[
            "METADATA",
            "RECORD",
            "top_level.txt",
            "pyproject.toml",
            ".python-version",
        ]
    }

    fn bounds(&self, config: &AnalyzerConfig) -> DependencyResolverBounds {
        DependencyResolverBounds {
            max_files_walked: config
                .python
                .environment
                .as_ref()
                .map(|environment| environment.limits.max_files_per_distribution),
            ..READS_FILES_ONLY
        }
    }

    fn adjust_limits(&self, config: &AnalyzerConfig, limits: &mut DependencyPackLimits) {
        if let Some(environment) = &config.python.environment {
            limits.max_artifacts_per_dependency = limits
                .max_artifacts_per_dependency
                .max(environment.limits.max_files_per_distribution);
        }
    }

    fn resolve(
        &self,
        config: &AnalyzerConfig,
        project: &dyn Project,
        limits: &DependencyPackLimits,
        cancellation: Option<&crate::CancellationToken>,
    ) -> DependencyDiscoveryOutcome {
        resolve_python_semantic_pack_dependencies(&config.python, project, limits, cancellation)
    }
}

struct GoDependencyResolver;

impl DependencyResolver for GoDependencyResolver {
    fn adapter(&self) -> &'static dyn DependencyPackAdapter {
        &GoDependencyPackAdapter
    }

    fn dependency_inputs(&self) -> &'static [&'static str] {
        &["go.mod", "go.sum", "go.work", "go.work.sum", "modules.txt"]
    }

    fn bounds(&self, config: &AnalyzerConfig) -> DependencyResolverBounds {
        let discovery = &config.go.dependency_discovery;
        let runs_tools = discovery.mode != GoDependencyDiscoveryMode::Disabled;
        DependencyResolverBounds {
            subprocess: if runs_tools {
                // `go list` under the bounded-process runner, with a cleared
                // environment and the module cache the configuration names.
                SubprocessPolicy::OfflineBuildTools
            } else {
                SubprocessPolicy::Forbidden
            },
            wall_clock: runs_tools.then_some(discovery.timeout),
            ..READS_FILES_ONLY
        }
    }

    fn prepare(
        &self,
        config: &AnalyzerConfig,
        catalog: &SemanticPackCatalog,
        dependencies: &[crate::analyzer::semantic_model::ResolvedDependency],
        limits: &DependencyPackLimits,
        cancellation: Option<&crate::CancellationToken>,
    ) -> DependencyPackPreparationOutcome {
        if config.go.dependency_discovery.mode == GoDependencyDiscoveryMode::CuratedPackEvidence {
            prepare_compatible_installed_semantic_packs(catalog, dependencies, limits, cancellation)
        } else {
            prepare_dependency_semantic_packs(
                catalog,
                self.adapter(),
                dependencies,
                limits,
                cancellation,
            )
        }
    }

    fn resolve(
        &self,
        config: &AnalyzerConfig,
        project: &dyn Project,
        limits: &DependencyPackLimits,
        cancellation: Option<&crate::CancellationToken>,
    ) -> DependencyDiscoveryOutcome {
        resolve_go_semantic_pack_dependencies(&config.go, project, limits, cancellation)
    }
}

struct CargoDependencyResolver;

impl DependencyResolver for CargoDependencyResolver {
    fn adapter(&self) -> &'static dyn DependencyPackAdapter {
        &RustDependencyPackAdapter
    }

    fn dependency_inputs(&self) -> &'static [&'static str] {
        &["Cargo.toml", "Cargo.lock"]
    }

    fn bounds(&self, _config: &AnalyzerConfig) -> DependencyResolverBounds {
        READS_FILES_ONLY
    }

    fn resolve(
        &self,
        config: &AnalyzerConfig,
        project: &dyn Project,
        limits: &DependencyPackLimits,
        cancellation: Option<&crate::CancellationToken>,
    ) -> DependencyDiscoveryOutcome {
        resolve_rust_semantic_pack_dependencies(&config.rust, project, limits, cancellation)
    }
}

struct RubyDependencyResolver;

impl DependencyResolver for RubyDependencyResolver {
    fn adapter(&self) -> &'static dyn DependencyPackAdapter {
        &RubyDependencyPackAdapter
    }

    fn dependency_inputs(&self) -> &'static [&'static str] {
        &["Gemfile", "Gemfile.lock", "gems.locked"]
    }

    fn bounds(&self, _config: &AnalyzerConfig) -> DependencyResolverBounds {
        READS_FILES_ONLY
    }

    fn resolve(
        &self,
        config: &AnalyzerConfig,
        project: &dyn Project,
        limits: &DependencyPackLimits,
        cancellation: Option<&crate::CancellationToken>,
    ) -> DependencyDiscoveryOutcome {
        resolve_ruby_semantic_pack_dependencies(&config.ruby, project, limits, cancellation)
    }
}

struct ComposerDependencyResolver;

impl DependencyResolver for ComposerDependencyResolver {
    fn adapter(&self) -> &'static dyn DependencyPackAdapter {
        &crate::analyzer::php::PhpDependencyPackAdapter
    }

    fn dependency_inputs(&self) -> &'static [&'static str] {
        &["composer.json", "composer.lock", "installed.json"]
    }

    fn bounds(&self, _config: &AnalyzerConfig) -> DependencyResolverBounds {
        READS_FILES_ONLY
    }

    fn adjust_limits(&self, _config: &AnalyzerConfig, limits: &mut DependencyPackLimits) {
        // Composer emits one artifact per autoload rule so a PSR-4 prefix stays
        // bound to the files it admits. Discovery caps the rule count itself,
        // so the artifact budget only has to admit that cap.
        limits.max_artifacts_per_dependency = limits
            .max_artifacts_per_dependency
            .max(crate::analyzer::php::PHP_MAX_AUTOLOAD_RULES_PER_PACKAGE);
    }

    fn resolve(
        &self,
        config: &AnalyzerConfig,
        project: &dyn Project,
        limits: &DependencyPackLimits,
        cancellation: Option<&crate::CancellationToken>,
    ) -> DependencyDiscoveryOutcome {
        crate::analyzer::php::resolve_php_semantic_pack_dependencies(
            &config.php,
            project,
            limits,
            cancellation,
        )
    }
}

struct CppDependencyResolver;

impl DependencyResolver for CppDependencyResolver {
    fn adapter(&self) -> &'static dyn DependencyPackAdapter {
        &CppDependencyPackAdapter
    }

    fn dependency_inputs(&self) -> &'static [&'static str] {
        &["compile_commands.json"]
    }

    fn bounds(&self, _config: &AnalyzerConfig) -> DependencyResolverBounds {
        READS_FILES_ONLY
    }

    fn resolve(
        &self,
        _config: &AnalyzerConfig,
        project: &dyn Project,
        limits: &DependencyPackLimits,
        cancellation: Option<&crate::CancellationToken>,
    ) -> DependencyDiscoveryOutcome {
        resolve_cpp_semantic_pack_dependencies(project, limits, cancellation)
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
    ///
    /// Failure is per ecosystem (#2442). An ecosystem whose discovery is
    /// incomplete, or whose preparation is, contributes no evidence and leaves
    /// the whole outcome incomplete, but its siblings still activate: a
    /// workspace with an unreadable `Cargo.lock` used to lose its npm packs
    /// too, which is the same false-green shape as reporting a clean run from
    /// evidence that was never read. Only cancellation stops the transaction,
    /// because a cancelled token says the caller is gone rather than that one
    /// ecosystem is unreadable.
    ///
    /// Publication still requires something to publish: when every requested
    /// ecosystem failed, nothing is acquired and no host is asked to refresh.
    pub fn activate_dependency_packs(
        &self,
        config: &AnalyzerConfig,
        ecosystems: &[DependencyPackEcosystem],
        context: DependencyPackWorkspaceContext<'_>,
    ) -> DependencyPackActivationOutcome {
        let mut outcomes = Vec::with_capacity(ecosystems.len());
        let mut activation = context.activation.clone();
        let mut publication_evidence = Vec::with_capacity(ecosystems.len());
        let mut cancelled = false;

        // Dependency-pack work runs before the parse phase and is attributed to
        // the workspace as a whole, so a slow ecosystem looks like slow startup
        // with no further detail. The discover/prepare span pair is per
        // ecosystem on purpose: it names which resolver is spending the time and
        // separates discovery, which walks the workspace, from preparation,
        // which reads and generates packs.
        for ecosystem in ecosystems.iter().copied() {
            let resolver = ecosystem.resolver();
            let mut limits = context.limits;
            resolver.adjust_limits(config, &mut limits);
            let discovery = {
                let _scope = crate::profiling::scope_with(|| {
                    format!("semantic_pack.discover[{}]", ecosystem.label())
                });
                resolver.resolve(
                    config,
                    self.analyzer().project(),
                    &limits,
                    Some(context.cancellation),
                )
            };
            if discovery.cancelled {
                cancelled = true;
                outcomes.push(DependencyPackEcosystemOutcome {
                    ecosystem,
                    discovery,
                    preparation: None,
                });
                break;
            }
            if !discovery.complete {
                outcomes.push(DependencyPackEcosystemOutcome {
                    ecosystem,
                    discovery,
                    preparation: None,
                });
                continue;
            }
            let preparation = {
                let _scope = crate::profiling::scope_with(|| {
                    format!(
                        "semantic_pack.prepare[{},{} deps]",
                        ecosystem.label(),
                        discovery.dependencies.len()
                    )
                });
                resolver.prepare(
                    config,
                    context.catalog,
                    &discovery.dependencies,
                    &limits,
                    Some(context.cancellation),
                )
            };
            if preparation.cancelled {
                cancelled = true;
                outcomes.push(DependencyPackEcosystemOutcome {
                    ecosystem,
                    discovery,
                    preparation: Some(preparation),
                });
                break;
            }
            if !preparation.complete {
                outcomes.push(DependencyPackEcosystemOutcome {
                    ecosystem,
                    discovery,
                    preparation: Some(preparation),
                });
                continue;
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

        if cancelled
            || (!ecosystems.is_empty()
                && publication_evidence.is_empty()
                && activation.evidence.is_empty())
        {
            return DependencyPackActivationOutcome {
                ecosystems: outcomes,
                runtime: None,
                diagnostic_refresh_required: false,
            };
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

    /// Language-restricted [`Self::build_ephemeral_footgun`], and a footgun for
    /// the same reason: read that function's doc before calling this one. The
    /// persisted equivalent is [`Self::build_persisted_for_languages`].
    pub fn build_ephemeral_for_languages_footgun(
        project: Arc<dyn Project>,
        config: AnalyzerConfig,
        languages: &BTreeSet<Language>,
    ) -> Result<Self, StoreError> {
        let store_context = crate::analyzer::ephemeral_store_context(project.as_ref())?;
        Self::build_filtered(project, config, Some(languages), store_context, None)
    }

    /// Build an analyzer over a delete-on-drop temporary store, no matter what
    /// the project's [`Project::persistence_root`] says.
    ///
    /// Named a footgun because it usually is one. An ephemeral store forfeits
    /// all reuse: every run re-parses and re-persists the whole world into a
    /// database that is deleted when the analyzer drops, so the next run starts
    /// from nothing. [`Self::build_persisted`] and its siblings instead reuse
    /// content-addressed blobs across runs, and take the per-cache build lock
    /// across the whole reconciliation so concurrent builders on one database
    /// do not each parse the same missing set. A persisted request over a
    /// project with no [`Project::persistence_root`] is a hard error rather
    /// than a quiet downgrade, so this family of functions is the only door to
    /// a throwaway store and taking it is always a stated choice. Prefer
    /// persisted unless one of the following is your actual reason:
    ///
    /// - Session-only parse-error evidence. Tree-sitter ERROR nodes exist only
    ///   on a cold parse, so `IAnalyzer::parse_errors` is complete for the whole
    ///   workspace only when nothing was served from a warm cache.
    /// - An explicit do-not-write-here operator opt-out, for a checkout you do
    ///   not own and must leave byte-identical.
    /// - Deliberate cold-build measurement.
    /// - A partial file set over a *live* workspace root, such as a
    ///   changed-file-scoped view of it. Writing an on-disk cache under that
    ///   root's workspace identity would be actively wrong: a build publishes
    ///   workspace projection rows, and a partial file set must not become the
    ///   workspace's cached picture of itself.
    ///
    /// Tests are fine: a hermetic small fixture wants no cache to survive it.
    ///
    /// An immutable revision image is no longer such a case, however few of the
    /// revision's files one request selected. It goes through
    /// [`Self::build_revision_image`] and shares the repository's
    /// content-addressed cache, because a fact keyed by blob id, language
    /// storage key and generation describes those bytes for every consumer, not
    /// just the request that parsed them, and a selection of files cannot make
    /// a blob's facts partial. The workspace rows such a build publishes name a
    /// self-deleting export directory and are removed by the caller's
    /// [`SharedAnalyzerCache::claim_revision_workspace`] lease, which is the
    /// part a live root cannot have. That path no longer falls back here when a
    /// host's cache will not open either; it reports the failure. What still
    /// arrives here is the partial case above: a worktree image, whose file set
    /// is a slice of a live workspace.
    pub fn build_ephemeral_footgun(
        project: Arc<dyn Project>,
        config: AnalyzerConfig,
    ) -> Result<Self, StoreError> {
        let store_context = crate::analyzer::ephemeral_store_context(project.as_ref())?;
        Self::build_filtered(project, config, None, store_context, None)
    }

    /// Build an analyzer over one immutable revision image, publishing its
    /// parsed facts into the repository's shared content-addressed cache.
    ///
    /// The cache is keyed by Git blob id and language storage key, so the
    /// blobs of this revision that the cache has already seen are read rather
    /// than parsed, and the ones parsed here warm the cache for every later
    /// consumer. [`Self::build_filtered`] holds the per-cache build lock across
    /// the whole reconciliation, exactly as a worktree build does, so two
    /// builders never each parse the same missing set.
    ///
    /// `cache` of `None` means the caller deliberately wants this image kept
    /// out of the shared cache, not that the host lacks one: a cache that will
    /// not open is reported, never worked around. The case that reaches here is
    /// a worktree image, whose root is a live project root and whose file set
    /// is partial, so publishing under that workspace identity would replace
    /// the workspace's own picture of itself. The build then runs against an
    /// ephemeral store, which returns the same answers and differs only in
    /// having to parse every blob.
    ///
    /// `languages` of `Some` restricts which parsers run. A file graph has no
    /// edges between distinct usage ecosystems, so a caller that already knows
    /// the seed ecosystems retains the complete revision's files while skipping
    /// parsers whose facts cannot enter the requested reverse walk.
    ///
    /// `blobs` is the image's own inventory of Git blob ids, so identity
    /// resolution reads the ids the export's tree walk already produced instead
    /// of re-hashing the bytes it just wrote.
    ///
    /// With a cache, the caller must hold a
    /// [`SharedAnalyzerCache::claim_revision_workspace`] claim for `project`'s
    /// root for as long as the analyzer is used, so the workspace projection
    /// rows this build publishes for a temp-directory root do not outlive the
    /// request.
    pub(crate) fn build_revision_image(
        project: Arc<dyn Project>,
        config: AnalyzerConfig,
        languages: Option<&BTreeSet<Language>>,
        cache: Option<&SharedAnalyzerCache>,
        blobs: Arc<RevisionBlobIdentities>,
    ) -> Result<Self, StoreError> {
        let mut store_context = match cache {
            Some(cache) => {
                crate::analyzer::revision_image_store_context(project.as_ref(), cache.store())
            }
            None => crate::analyzer::ephemeral_store_context(project.as_ref())?,
        };
        store_context.revision_blobs = Some(blobs);
        Self::build_filtered(project, config, languages, store_context, None)
    }

    /// Build an analyzer and retain the tier crossings paid while constructing
    /// it. The observer is finished before the result is returned, so later
    /// incremental work cannot contaminate the open report.
    ///
    /// A footgun for the reason given on [`Self::build_ephemeral_footgun`], with
    /// one narrowing: measuring the tier crossings of a cold build is itself a
    /// legitimate reason to want one. If you are measuring anything else, use
    /// [`Self::build_persisted_with_tier_access`].
    #[doc(hidden)]
    pub fn build_ephemeral_with_tier_access_footgun(
        project: Arc<dyn Project>,
        config: AnalyzerConfig,
    ) -> Result<(Self, Arc<AnalyzerBuildTierAccess>), StoreError> {
        let observer = Arc::new(AnalyzerBuildTierAccess::new_active());
        let mut store_context = crate::analyzer::ephemeral_store_context(project.as_ref())?;
        store_context.build_tier_access = Arc::clone(&observer);
        let workspace = Self::build_filtered(project, config, None, store_context, None)?;
        observer.finish();
        Ok((workspace, observer))
    }

    pub fn build_persisted(
        project: Arc<dyn Project>,
        config: AnalyzerConfig,
    ) -> Result<Self, StoreError> {
        Self::build_persisted_inner(project, config, None, true, None)
    }

    /// Language-restricted [`Self::build_persisted`]: the same shared
    /// content-addressed cache, with only the requested languages' parsers run.
    ///
    /// Restricting languages narrows which per-language delegates are built. It
    /// does not narrow what stays in the cache: garbage collection reaches from
    /// git refs and the uncommitted working set, which say nothing about
    /// language, so an unselected language's facts survive this build and a
    /// later whole-workspace build reuses them.
    pub fn build_persisted_for_languages(
        project: Arc<dyn Project>,
        config: AnalyzerConfig,
        languages: &BTreeSet<Language>,
    ) -> Result<Self, StoreError> {
        let store_context = crate::analyzer::persistent_store_context(project.as_ref())?;
        Self::build_filtered(project, config, Some(languages), store_context, None)
    }

    /// Build a persisted analyzer whose cache is collected only when the host
    /// explicitly requests it.
    pub fn build_persisted_without_automatic_gc(
        project: Arc<dyn Project>,
        config: AnalyzerConfig,
    ) -> Result<Self, StoreError> {
        Self::build_persisted_inner(project, config, None, false, None)
    }

    /// Persisted counterpart of [`Self::build_ephemeral_with_tier_access_footgun`].
    #[doc(hidden)]
    pub fn build_persisted_with_tier_access(
        project: Arc<dyn Project>,
        config: AnalyzerConfig,
    ) -> Result<(Self, Arc<AnalyzerBuildTierAccess>), StoreError> {
        let observer = Arc::new(AnalyzerBuildTierAccess::new_active());
        let workspace =
            Self::build_persisted_inner(project, config, None, true, Some(Arc::clone(&observer)))?;
        observer.finish();
        Ok((workspace, observer))
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
        Self::build_persisted_inner(project, config, Some(Arc::new(progress)), true, None)
    }

    fn build_persisted_inner(
        project: Arc<dyn Project>,
        config: AnalyzerConfig,
        progress: Option<BuildProgress>,
        automatic_gc: bool,
        tier_access: Option<Arc<AnalyzerBuildTierAccess>>,
    ) -> Result<Self, StoreError> {
        let mut store_context = if automatic_gc {
            crate::analyzer::persistent_store_context(project.as_ref())?
        } else {
            crate::analyzer::persistent_store_context_without_automatic_gc(project.as_ref())?
        };
        if let Some(tier_access) = tier_access {
            store_context.build_tier_access = tier_access;
        }
        Self::build_filtered(project, config, None, store_context, progress)
    }

    fn build_filtered(
        project: Arc<dyn Project>,
        config: AnalyzerConfig,
        requested_languages: Option<&BTreeSet<Language>>,
        store_context: crate::analyzer::AnalyzerStoreContext,
        progress: Option<BuildProgress>,
    ) -> Result<Self, StoreError> {
        let _scope = profiling::scope("WorkspaceAnalyzer::build");
        // Persisted workspaces share parsed blobs, so serialize the complete
        // reconciliation, not just the first population. Otherwise concurrent
        // worktrees all snapshot the same missing set and each creates a full
        // analyzer pool before any of them can publish reusable results.
        let build_lock = if let Some(db_path) = store_context.store.db_path() {
            profiling::note("workspace.store=persistent");
            Some(WorkspaceBuildLock::acquire(db_path)?)
        } else {
            profiling::note("workspace.store=ephemeral");
            None
        };
        // A fresh abort per fan-out. The caller's context may outlive this
        // build and go on to serve lazy per-language delegate builds, and those
        // must not inherit a flag this build set.
        let mut store_context = crate::analyzer::AnalyzerStoreContext {
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
        #[cfg(test)]
        let startup_oid_batches = store_context
            .liveness
            .as_ref()
            .map(|liveness| liveness.startup_oid_batch_counter());
        // Capture one immutable listing and one startup identity projection
        // before the language fan-out. The snapshot is consumed by delegate
        // construction and cleared before the retained build context is made,
        // so watcher-driven updates never serve stale startup state.
        store_context.workspace_snapshot = WorkspaceBuildSnapshot::capture(
            project.as_ref(),
            store_context.liveness.as_deref(),
            &selected_languages,
        );
        store_context.workspace_listing_complete = store_context.workspace_snapshot.is_some();
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

        store_context.workspace_snapshot = None;

        let build_context = WorkspaceBuildContext::new(
            Arc::clone(&project),
            config,
            store_context,
            requested_languages.cloned(),
        );
        #[cfg(test)]
        let build_context =
            build_context.with_startup_oid_batch_counter_for_test(startup_oid_batches);
        let build_context = Arc::new(build_context);

        let workspace = if delegates.is_empty() {
            Self::Empty(EmptyAnalyzer::new_for_workspace(build_context))
        } else {
            Self::Multi(Box::new(MultiAnalyzer::new_for_workspace(
                delegates,
                build_context,
            )))
        };
        drop(build_lock);
        Ok(workspace)
    }

    pub fn analyzer(&self) -> &dyn IAnalyzer {
        match self {
            Self::Empty(analyzer) => analyzer,
            Self::Multi(analyzer) => analyzer.as_ref(),
        }
    }

    #[cfg(test)]
    pub(crate) fn startup_oid_batch_count_for_test(&self) -> usize {
        match self {
            Self::Empty(analyzer) => analyzer
                .build_context
                .as_deref()
                .map_or(0, WorkspaceBuildContext::startup_oid_batch_count_for_test),
            Self::Multi(analyzer) => analyzer
                .build_context()
                .map_or(0, WorkspaceBuildContext::startup_oid_batch_count_for_test),
        }
    }

    /// The on-disk path of the analyzer store this workspace persists to, or
    /// `None` when the store has no persistent workspace identity, which now
    /// means exactly one thing: this was an ephemeral build. A persisted build
    /// over a project with no [`Project::persistence_root`] fails rather than
    /// degrading, so a workspace from a persisted build always reports a path.
    /// `None` does not mean the store has no file. An ephemeral store is a
    /// delete-on-drop temporary database rather than `:memory:`, so the reader
    /// pool can share it; what it lacks is an identity that outlives the build.
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
    pub fn semantic_artifact_key_is_current_with_source_bytes(
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
    use crate::analyzer::semantic_model::{
        CompilerOptions, SemanticModelActivationEvidence, SemanticModelRuntimeLimits,
        SessionPackSource, SessionPackSourceKind, SourceFormat, compile_source,
    };
    use crate::analyzer::store::liveness::Liveness;
    use crate::analyzer::{
        FilesystemProject, MultiRootProject, OverlayProject, Project, ProjectFile, TestProject,
    };
    use crate::gitblob::test_repo::{commit_all, init_repo};
    use rusqlite::Connection;
    use std::sync::atomic::Ordering;

    use crate::inline_project::InlineTestProject;

    #[test]
    fn intrinsic_models_activate_when_dependency_discovery_fails() {
        let project = InlineTestProject::with_language(Language::Go)
            .file("main.go", "package main\n")
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let catalog = SemanticPackCatalog::open_ephemeral(Default::default()).unwrap();
        let pack = compile_source(
            SourceFormat::Json,
            br#"{
              "schema_version": 1,
              "pack_id": "test.go.intrinsic",
              "version": "1.0.0",
              "producer": {"name": "test", "version": "1.0.0"},
              "language": "go",
              "ecosystem": "go",
              "compatibility": {"bifrost": ">=0.10.0, <1.0.0"},
              "provenance": {"source": "test:go-intrinsic"},
              "license": "Apache-2.0",
              "completeness": "complete",
              "safety": {"generated_code_only": false, "review_required": false},
              "shards": [{
                "id": "summaries",
                "activation": [{}],
                "payload": {
                  "kind": "procedure_summaries",
                  "summaries": [{
                    "id": "test.go.exit",
                    "target": {
                      "path": "src/os/proc.go",
                      "symbol": "os.Exit(code int)",
                      "has_receiver": false,
                      "parameter_count": 1
                    },
                    "completeness": "complete",
                    "normal_continuation_absent": true,
                    "transfers": [],
                    "effects": [{
                      "kind": "unknown_call_boundary",
                      "event": "test.go.exit-boundary"
                    }]
                  }]
                }
              }]
            }"#,
            &CompilerOptions::default(),
        )
        .unwrap_or_else(|diagnostics| panic!("intrinsic fixture failed: {diagnostics:#?}"));
        catalog
            .register_session_pack(
                &pack,
                &SessionPackSource {
                    kind: SessionPackSourceKind::Embedded,
                    source_id: "test:go-intrinsic".to_owned(),
                },
            )
            .unwrap();

        let mut config = AnalyzerConfig::default();
        config.go.dependency_discovery.mode = GoDependencyDiscoveryMode::CuratedPackEvidence;
        config.go.dependency_discovery.go_executable = Some(project.root().join("missing-go"));
        let request = SemanticModelActivationRequest {
            bifrost_version: semver::Version::parse(env!("CARGO_PKG_VERSION")).unwrap(),
            evidence: vec![SemanticModelActivationEvidence {
                language: "go".to_owned(),
                ecosystem: "go".to_owned(),
                package: None,
                module: None,
                toolchain: None,
                target: None,
                configuration: None,
                artifact_sha256: None,
            }],
            controls: Vec::new(),
            limits: SemanticModelRuntimeLimits::default(),
        };
        let outcome = workspace.activate_dependency_packs(
            &config,
            &[DependencyPackEcosystem::Go],
            DependencyPackWorkspaceContext {
                catalog: &catalog,
                persistence: None,
                activation: &request,
                limits: DependencyPackLimits::default(),
                cancellation: &crate::CancellationToken::default(),
            },
        );

        assert!(!outcome.complete());
        assert!(outcome.diagnostic_refresh_required);
        assert!(!outcome.ecosystems[0].discovery.complete);
        assert!(outcome.ecosystems[0].preparation.is_none());
        let SemanticModelRuntimeOutcome::Ready { active, .. } = outcome
            .runtime
            .expect("intrinsic activation must still run")
        else {
            panic!("intrinsic activation should be ready")
        };
        assert_eq!(active.shards().len(), 1);
        assert_eq!(active.shards()[0].manifest.pack_id, "test.go.intrinsic");
    }

    #[test]
    fn git_multilanguage_build_reuses_constructor_listing_and_one_oid_batch() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        std::fs::write(root.join("Sample.java"), "class Sample {}\n").unwrap();
        std::fs::write(root.join("sample.py"), "class SamplePy:\n    pass\n").unwrap();
        let repository = init_repo(&root);
        commit_all(&repository, "multi-language workspace");

        let project = Arc::new(FilesystemProject::new(&root).unwrap());
        let workspace = WorkspaceAnalyzer::build_ephemeral_footgun(
            Arc::clone(&project) as Arc<dyn Project>,
            AnalyzerConfig::default(),
        )
        .expect("ephemeral multi-language workspace");

        assert_eq!(
            project.workspace_file_listing_count(),
            1,
            "the constructor listing should seed the one build snapshot"
        );
        assert_eq!(workspace.startup_oid_batch_count_for_test(), 1);
        assert!(
            workspace
                .analyzer()
                .declarations(&ProjectFile::new(&root, "Sample.java"))
                .iter()
                .any(|unit| unit.identifier() == "Sample")
        );
        assert!(
            workspace
                .analyzer()
                .declarations(&ProjectFile::new(&root, "sample.py"))
                .iter()
                .any(|unit| unit.identifier() == "SamplePy")
        );

        let late = ProjectFile::new(&root, "late.go");
        std::fs::write(late.abs_path(), "package late\n").unwrap();
        assert!(project.all_files_shared().unwrap().contains(&late));
        assert_eq!(
            project.workspace_file_listing_count(),
            2,
            "manual sessions must return to a fresh walk after the build seed"
        );
    }

    #[test]
    fn non_git_multilanguage_build_reuses_one_listing_without_live_oids() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        std::fs::write(root.join("Sample.java"), "class Sample {}\n").unwrap();
        std::fs::write(root.join("sample.py"), "class SamplePy:\n    pass\n").unwrap();
        let project = Arc::new(TestProject::from_root_with_inferred_languages(&root).unwrap());
        let workspace = WorkspaceAnalyzer::build_ephemeral_footgun(
            Arc::clone(&project) as Arc<dyn Project>,
            AnalyzerConfig::default(),
        )
        .expect("ephemeral non-Git workspace");

        assert_eq!(project.workspace_file_listing_count(), 1);
        assert_eq!(workspace.startup_oid_batch_count_for_test(), 0);
        assert!(workspace.analyzer().languages().contains(&Language::Java));
        assert!(workspace.analyzer().languages().contains(&Language::Python));
    }

    #[test]
    fn multi_root_build_consumes_each_constructor_seed_once() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let java_root = root.join("java");
        let python_root = root.join("python");
        std::fs::create_dir_all(&java_root).unwrap();
        std::fs::create_dir_all(&python_root).unwrap();
        std::fs::write(java_root.join("Sample.java"), "class Sample {}\n").unwrap();
        std::fs::write(python_root.join("sample.py"), "class SamplePy:\n    pass\n").unwrap();

        let project = Arc::new(MultiRootProject::new([java_root, python_root]).unwrap());
        let workspace = WorkspaceAnalyzer::build_ephemeral_footgun(
            Arc::clone(&project) as Arc<dyn Project>,
            AnalyzerConfig::default(),
        )
        .expect("ephemeral multi-root workspace");

        assert_eq!(project.workspace_file_listing_count(), 2);
        assert!(workspace.analyzer().languages().contains(&Language::Java));
        assert!(workspace.analyzer().languages().contains(&Language::Python));

        let late = root.join("java").join("late.go");
        std::fs::write(&late, "package late\n").unwrap();
        let late_file = ProjectFile::new(&root, "java/late.go");
        assert!(project.all_files_shared().unwrap().contains(&late_file));
        assert_eq!(project.workspace_file_listing_count(), 4);
    }

    #[test]
    fn build_snapshot_hashes_overlay_source_once_as_an_overlay_entry() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let file = ProjectFile::new(&root, "Sample.java");
        std::fs::write(file.abs_path(), "class Disk {}\n").unwrap();
        let repository = init_repo(&root);
        commit_all(&repository, "overlay source");

        let base: Arc<dyn Project> = Arc::new(FilesystemProject::new(&root).unwrap());
        let overlay = Arc::new(OverlayProject::new(base));
        let overlay_source = "class Overlay {}\n";
        assert!(overlay.set(file.abs_path(), overlay_source.to_owned()));
        let repository = crate::gitblob::discover(&root).unwrap();
        let liveness = Liveness::new(repository).unwrap();
        let snapshot =
            WorkspaceBuildSnapshot::capture(overlay.as_ref(), Some(&liveness), &[Language::Java])
                .expect("Git-backed overlay snapshot");
        let entry = snapshot
            .live_entry(overlay.as_ref(), &file)
            .expect("overlay live entry");
        assert_eq!(
            liveness.startup_oid_batch_counter().load(Ordering::Relaxed),
            0
        );
        let expected =
            git2::Oid::hash_object(git2::ObjectType::Blob, overlay_source.as_bytes()).unwrap();
        assert_eq!(entry.oid(), expected);
        assert!(entry.is_overlay());

        let updated_overlay_source = "class OverlayTwo {}\n";
        assert!(overlay.set(file.abs_path(), updated_overlay_source.to_owned()));
        assert!(snapshot.live_entry(overlay.as_ref(), &file).is_none());
        let refreshed =
            WorkspaceBuildSnapshot::capture(overlay.as_ref(), Some(&liveness), &[Language::Java])
                .expect("refreshed overlay snapshot");
        let refreshed_entry = refreshed
            .live_entry(overlay.as_ref(), &file)
            .expect("refreshed overlay live entry");
        let refreshed_expected =
            git2::Oid::hash_object(git2::ObjectType::Blob, updated_overlay_source.as_bytes())
                .unwrap();
        assert_eq!(refreshed_entry.oid(), refreshed_expected);

        let workspace = WorkspaceAnalyzer::build_ephemeral_footgun(
            Arc::clone(&overlay) as Arc<dyn Project>,
            AnalyzerConfig::default(),
        )
        .expect("ephemeral overlay workspace");
        assert!(
            workspace
                .analyzer()
                .declarations(&file)
                .iter()
                .any(|unit| unit.identifier() == "OverlayTwo")
        );
    }

    #[test]
    fn build_snapshot_rejects_changed_disk_identity_and_recomputes() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let file = ProjectFile::new(&root, "Sample.java");
        std::fs::write(file.abs_path(), "class Disk {}").unwrap();
        let repository = init_repo(&root);
        commit_all(&repository, "disk source");

        let project = FilesystemProject::new(&root).unwrap();
        let repository = crate::gitblob::discover(&root).unwrap();
        let liveness = Liveness::new(repository).unwrap();
        let snapshot =
            WorkspaceBuildSnapshot::capture(&project, Some(&liveness), &[Language::Java])
                .expect("Git-backed disk snapshot");
        let old_oid = snapshot
            .live_entry(&project, &file)
            .expect("disk live entry")
            .oid();

        std::fs::write(file.abs_path(), "class DiskUpdated {}").unwrap();
        assert!(snapshot.live_entry(&project, &file).is_none());

        let refreshed =
            WorkspaceBuildSnapshot::capture(&project, Some(&liveness), &[Language::Java])
                .expect("refreshed disk snapshot");
        let new_oid = refreshed
            .live_entry(&project, &file)
            .expect("refreshed disk live entry")
            .oid();
        assert_ne!(old_oid, new_oid);
    }

    #[test]
    fn semantic_generation_check_rejects_a_stale_configuration_identity() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let file = ProjectFile::new(root.clone(), "src/generation.ts");
        file.write("export const generation = 1;\n").unwrap();
        let project: Arc<dyn Project> = Arc::new(TestProject::new(root, Language::TypeScript));
        let workspace =
            WorkspaceAnalyzer::build_ephemeral_footgun(project, AnalyzerConfig::default())
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
        let single = WorkspaceAnalyzer::build_ephemeral_footgun(single, AnalyzerConfig::default())
            .expect("ephemeral workspace should build");
        assert!(!single.query_indexes_warm());
        single.warm_query_indexes();
        assert!(single.query_indexes_warm());

        let multi: Arc<dyn Project> = Arc::new(TestProject::with_languages(
            root,
            BTreeSet::from([Language::Rust, Language::Java]),
        ));
        let multi = WorkspaceAnalyzer::build_ephemeral_footgun(multi, AnalyzerConfig::default())
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
        let rust = WorkspaceAnalyzer::build_ephemeral_footgun(rust, AnalyzerConfig::default())
            .expect("ephemeral workspace should build");
        assert!(rust.rust_usage_facts_ready());
        assert!(!rust.rust_usage_facts_warm());
        rust.warm_rust_usage_facts();
        assert!(rust.rust_usage_facts_ready());
        assert!(rust.rust_usage_facts_warm());

        let java: Arc<dyn Project> = Arc::new(TestProject::new(root, Language::Java));
        let java = WorkspaceAnalyzer::build_ephemeral_footgun(java, AnalyzerConfig::default())
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
        let workspace = WorkspaceAnalyzer::build_ephemeral_footgun(Arc::clone(&project), config)
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
        let disk_provider = disk_workspace.analyzer().structural_fact_providers()[0];
        let disk_facts = disk_provider.structural_facts(&file).unwrap();
        let disk_fact_count = disk_facts.nodes().len();
        assert_eq!(disk_facts.source(), disk_source);

        let overlay = Arc::new(OverlayProject::new(Arc::clone(&project)));
        assert!(overlay.set(file.abs_path(), overlay_source.to_owned()));
        let overlay_workspace =
            disk_workspace.clone_with_project(Arc::clone(&overlay) as Arc<dyn Project>);
        let overlay_provider = overlay_workspace.analyzer().structural_fact_providers()[0];
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
        let disk_provider = disk_reopened.analyzer().structural_fact_providers()[0];
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
        let committed_fact_manifests = Connection::open(
            root.join(".bifrost/cache")
                .join(crate::cache_db::cache_db_file_name()),
        )
        .unwrap()
        .query_row(
            "SELECT COUNT(*) FROM structural_fact_manifests
                 WHERE blob_id = (
                   SELECT id FROM blobs
                   WHERE blob_oid = ?1 AND lang = 'typescript:ts'
                 )",
            [disk_oid.to_string()],
            |row| row.get::<_, usize>(0),
        )
        .unwrap();
        assert_eq!(
            committed_fact_manifests, 1,
            "overlay analysis must not replace the committed source facts"
        );
    }
}
