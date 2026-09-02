use std::path::PathBuf;
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnalyzerConfig {
    pub parallelism: Option<usize>,
    pub memo_cache_budget_bytes: Option<u64>,
    /// Which class-hierarchy expansions call dispatch may add beyond the
    /// callee the static types already name.
    pub dispatch_hierarchy_expansion: DispatchHierarchyExpansion,
    pub rust: RustAnalyzerConfig,
    pub jvm: JvmAnalyzerConfig,
    pub csharp: CSharpAnalyzerConfig,
    pub js_ts: JsTsAnalyzerConfig,
    pub go: GoAnalyzerConfig,
    pub python: PythonAnalyzerConfig,
    pub ruby: RubyAnalyzerConfig,
    pub php: PhpAnalyzerConfig,
}

/// Which class-hierarchy expansions call dispatch may add beyond the callee a
/// call's static types already name.
///
/// "Class-hierarchy expansion" means: after dispatch resolves a call to a
/// method declaration, also offer the workspace methods that implement or
/// override that declaration as further things the call could reach. Every
/// expansion here adds *candidates*, never proven call edges.
///
/// Two expansions exist, and only one of them is a policy question.
///
/// The declaration that has no body at all -- an interface method or an
/// abstract method -- is always expanded, and is not represented in this type.
/// Without expansion there is nothing to analyze at that call, so offering the
/// implementations cannot widen anything: it is the only way to name code that
/// runs.
///
/// The declaration that *does* have a body is the policy question, and it is
/// [`Self::concrete_overrides`]. A concrete method that subclasses override can
/// really dispatch to any of those overrides, but the callee the static types
/// name is already analyzable, so expanding strictly widens the candidate set
/// and can only add wrong answers as well as right ones. It is therefore off by
/// default, and enabling it is a measured decision rather than a default.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DispatchHierarchyExpansion {
    /// Offer the workspace overrides of a *concrete* resolved method as further
    /// dispatch candidates. Off by default.
    pub concrete_overrides: bool,
}

impl DispatchHierarchyExpansion {
    /// Every expansion that is a policy question turned off: exactly the
    /// behavior a build has when nothing opts in.
    pub const OFF: Self = Self {
        concrete_overrides: false,
    };

    /// Only the concrete-override expansion turned on.
    pub const CONCRETE_OVERRIDES: Self = Self {
        concrete_overrides: true,
    };

    /// The expansion a production analyzer starts from, read once from the
    /// process environment.
    ///
    /// `BIFROST_CHA_CONCRETE_OVERRIDES` set to anything turns the
    /// concrete-override expansion on. The value is read once because a corpus
    /// run constructs analyzers repeatedly and re-reading the environment would
    /// show up in the measurement the switch exists to take. Tests must set
    /// [`AnalyzerConfig::dispatch_hierarchy_expansion`] directly instead of
    /// setting the variable: test threads share one process environment.
    pub fn from_environment() -> Self {
        static ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
        let concrete_overrides =
            *ENABLED.get_or_init(|| std::env::var_os("BIFROST_CHA_CONCRETE_OVERRIDES").is_some());
        Self { concrete_overrides }
    }
}

/// Explicit, passive evidence for Composer dependency API-pack ingestion.
///
/// Bifrost reads the named metadata files and the installed package trees below
/// the approved vendor roots. It never runs Composer, a Composer script, a
/// Composer plugin, or any dependency code, and it never opens a network
/// connection.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PhpAnalyzerConfig {
    pub dependency_api_evidence: Vec<PhpDependencyApiEvidence>,
}

/// One exact Composer install whose API surface a host approves for indexing.
///
/// Unlike Ruby, the host does not repeat the package list: `composer.lock` is
/// itself the exact package inventory, and `lockfile_sha256` pins the revision
/// this evidence describes. What the host must still state explicitly is where
/// installed package trees may be read from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PhpDependencyApiEvidence {
    /// `composer.lock`. Relative paths resolve against the project root.
    pub lockfile_path: PathBuf,
    /// Lowercase SHA-256 of the exact lockfile this evidence describes.
    pub lockfile_sha256: String,
    /// `vendor/composer/installed.json`, which records the install path and the
    /// autoload rules Composer actually wrote. Absent evidence falls back to
    /// the autoload block in `composer.lock` and the conventional
    /// `<vendor root>/<package name>` install path.
    pub installed_json_path: Option<PathBuf>,
    /// Lowercase SHA-256 of `installed_json_path` when that path is present.
    pub installed_json_sha256: Option<String>,
    /// The PHP runtime whose platform requirements the lock was solved for.
    pub php_version: String,
    /// Roots that contain the installed package trees. A package whose install
    /// directory escapes every approved root is not read.
    pub approved_vendor_roots: Vec<PathBuf>,
    /// Index `packages-dev` in addition to `packages`.
    pub include_dev_packages: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RubyAnalyzerConfig {
    /// Explicit, passive evidence for Ruby dependency API-pack ingestion.
    /// Bifrost reads these files but never invokes Ruby, Bundler, or gem hooks.
    pub dependency_api_evidence: Vec<RubyDependencyApiEvidence>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RubyDependencyApiEvidence {
    pub lockfile_path: PathBuf,
    pub lockfile_sha256: String,
    pub ruby_version: String,
    pub platform: String,
    /// Roots containing the exact archives listed in `gems`. Relative paths
    /// are resolved against the project root.
    pub approved_archive_roots: Vec<PathBuf>,
    pub gems: Vec<RubyGemApiArtifact>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RubyGemApiArtifact {
    pub name: String,
    pub version: String,
    pub source: String,
    pub checksum: Option<String>,
    pub gem_archive_path: PathBuf,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct JsTsAnalyzerConfig {
    pub dependency_discovery: JsTsDependencyDiscoveryConfig,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JsTsDependencyDiscoveryConfig {
    /// Exact npm lockfiles to inspect. Relative paths are resolved against the project root.
    pub lockfile_paths: Vec<PathBuf>,
    /// Installed package roots to approve. Relative paths are resolved against the project root.
    pub node_modules_roots: Vec<PathBuf>,
    /// Inspect root `package-lock.json` and `npm-shrinkwrap.json` after explicit lockfiles.
    pub discover_workspace_lockfiles: bool,
    pub max_lockfile_bytes: u64,
    pub max_package_manifest_bytes: u64,
}

impl Default for JsTsDependencyDiscoveryConfig {
    fn default() -> Self {
        Self {
            lockfile_paths: Vec::new(),
            node_modules_roots: Vec::new(),
            discover_workspace_lockfiles: true,
            max_lockfile_bytes: 32 * 1024 * 1024,
            max_package_manifest_bytes: 1024 * 1024,
        }
    }
}

/// Explicit, static Python-environment selection. Bifrost never discovers an
/// interpreter or a package cache implicitly: callers must name every root
/// whose files may participate in external API-pack discovery.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PythonAnalyzerConfig {
    pub environment: Option<PythonEnvironmentConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PythonEnvironmentConfig {
    pub implementation: String,
    pub version: String,
    /// The interpreter's own `sys.platform` value, for example `linux`,
    /// `darwin`, or `win32`.
    ///
    /// This is the activation target for every pack the environment produces,
    /// and a stub's `sys.platform` guard names targets in the same vocabulary.
    /// A value from another vocabulary would compare against those guards as
    /// an ordinary mismatch and could hide a declaration the interpreter has,
    /// so hosts must report the interpreter's value and nothing else.
    pub platform: String,
    pub standard_library_root: PathBuf,
    pub bundled_stub_roots: Vec<PathBuf>,
    pub distribution_roots: Vec<PathBuf>,
    pub limits: PythonEnvironmentLimits,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PythonEnvironmentLimits {
    pub max_directories: usize,
    pub max_distributions: usize,
    pub max_files_per_distribution: usize,
    pub max_metadata_bytes: u64,
    pub max_total_candidate_bytes: u64,
    pub max_diagnostics: usize,
    pub max_diagnostic_message_bytes: usize,
}

impl Default for PythonEnvironmentLimits {
    fn default() -> Self {
        Self {
            max_directories: 16_384,
            max_distributions: 4_096,
            max_files_per_distribution: 16_384,
            max_metadata_bytes: 1024 * 1024,
            max_total_candidate_bytes: 512 * 1024 * 1024,
            max_diagnostics: 256,
            max_diagnostic_message_bytes: 4 * 1024,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RustAnalyzerConfig {
    /// Explicit, passive evidence bundles for dependency API-pack ingestion.
    /// Bifrost reads these files but never invokes Cargo or rustdoc.
    pub dependency_api_evidence: Vec<RustDependencyApiEvidence>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RustDependencyApiEvidence {
    pub metadata_path: PathBuf,
    pub lockfile_path: PathBuf,
    pub target: String,
    pub configuration: String,
    pub selected_targets: Vec<RustSelectedTarget>,
    pub packages: Vec<RustPackageApiArtifact>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RustSelectedTarget {
    pub package_id: String,
    pub target_name: String,
    pub target_kind: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RustPackageApiArtifact {
    pub package_id: String,
    pub crate_name: String,
    pub enabled_features: Vec<String>,
    pub rustdoc_json_path: PathBuf,
    pub rustdoc_toolchain: String,
    pub rustdoc_format_version: u32,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GoAnalyzerConfig {
    pub dependency_discovery: GoDependencyDiscoveryConfig,
}

/// How a host uses the exact package graph reported by the Go toolchain.
///
/// Curated-pack evidence is intentionally distinct from full dependency-pack
/// production. The former needs only the exact reachable module coordinates
/// that can select an already installed reviewed pack; the latter reads every
/// reachable dependency source set and may generate a declaration pack for
/// each one.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum GoDependencyDiscoveryMode {
    /// Do not invoke the Go toolchain or publish dependency evidence.
    #[default]
    Disabled,
    /// Discover exact reachable modules for compatible installed-pack
    /// activation, without reading dependency sources or generating packs.
    CuratedPackEvidence,
    /// Discover exact reachable source sets and prepare dependency packs for
    /// the complete dependency surface.
    FullProduction,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoDependencyDiscoveryConfig {
    /// Go dependency discovery is opt-in because every enabled mode invokes
    /// the configured Go toolchain. Full production can additionally index a
    /// large local module graph.
    pub mode: GoDependencyDiscoveryMode,
    /// Go executable to use. Relative names are resolved by the parent
    /// process before the hardened child environment is installed.
    pub go_executable: Option<PathBuf>,
    /// Package patterns passed directly to `go list`.
    pub workspace_patterns: Vec<String>,
    pub gopath: Option<PathBuf>,
    pub gomodcache: Option<PathBuf>,
    pub goos: Option<String>,
    pub goarch: Option<String>,
    pub build_tags: Vec<String>,
    pub timeout: Duration,
}

impl Default for GoDependencyDiscoveryConfig {
    fn default() -> Self {
        Self {
            mode: GoDependencyDiscoveryMode::Disabled,
            go_executable: None,
            workspace_patterns: vec!["./...".to_owned()],
            gopath: None,
            gomodcache: None,
            goos: None,
            goarch: None,
            build_tags: Vec::new(),
            timeout: Duration::from_secs(30),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CSharpAnalyzerConfig {
    /// Extra assemblies to index in addition to already-restored project assets.
    pub assembly_paths: Vec<PathBuf>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct JvmAnalyzerConfig {
    pub external_dependencies: JvmExternalDependencies,
    pub dependency_discovery: JvmDependencyDiscoveryConfig,
    pub standard_library_discovery: JvmStandardLibraryDiscoveryConfig,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JvmStandardLibraryDiscoveryConfig {
    /// Exact JDK homes to inspect before the process environment. Relative
    /// paths are resolved against the project root.
    pub jdk_homes: Vec<PathBuf>,
    /// Inspect the process `JAVA_HOME` after configured homes.
    pub discover_java_home: bool,
}

impl Default for JvmStandardLibraryDiscoveryConfig {
    fn default() -> Self {
        Self {
            jdk_homes: Vec::new(),
            discover_java_home: true,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct JvmExternalDependencies {
    pub artifact_paths: Vec<JvmExternalArtifact>,
    pub coordinates: Vec<JvmMavenCoordinate>,
    pub repository_roots: Vec<PathBuf>,
    pub gradle_cache_roots: Vec<PathBuf>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum JvmDependencyDiscoveryMode {
    Disabled,
    #[default]
    Metadata,
    OfflineBuildTools,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JvmDependencyDiscoveryConfig {
    pub mode: JvmDependencyDiscoveryMode,
    pub maven_executable: Option<PathBuf>,
    pub gradle_executable: Option<PathBuf>,
    pub timeout: Duration,
}

impl Default for JvmDependencyDiscoveryConfig {
    fn default() -> Self {
        Self {
            mode: JvmDependencyDiscoveryMode::Metadata,
            maven_executable: None,
            gradle_executable: None,
            timeout: Duration::from_secs(30),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct JvmExternalArtifact {
    pub artifact_path: PathBuf,
    pub source_artifact_path: Option<PathBuf>,
    /// Exact coordinate evidence when the path came from dependency metadata
    /// or an offline build-tool report. Explicit paths leave this unset.
    pub coordinate: Option<JvmMavenCoordinate>,
    pub origin: JvmExternalArtifactOrigin,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum JvmExternalArtifactOrigin {
    #[default]
    Explicit,
    MavenReport,
    GradleReport,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct JvmMavenCoordinate {
    pub group_id: String,
    pub artifact_id: String,
    pub version: String,
}

impl JvmMavenCoordinate {
    pub fn new(
        group_id: impl Into<String>,
        artifact_id: impl Into<String>,
        version: impl Into<String>,
    ) -> Self {
        Self {
            group_id: group_id.into(),
            artifact_id: artifact_id.into(),
            version: version.into(),
        }
    }
}

/// Default analyzer thread-pool size. Honors `BIFROST_PARALLELISM` (a positive integer)
/// so batch consumers running many analyzers concurrently can cap each pool and avoid
/// oversubscribing cores / exhausting the process thread budget; otherwise uses all cores.
fn default_parallelism() -> usize {
    if let Ok(raw) = std::env::var("BIFROST_PARALLELISM")
        && let Ok(value) = raw.trim().parse::<usize>()
        && value > 0
    {
        return value;
    }
    std::thread::available_parallelism()
        .map(|value| value.get())
        .unwrap_or(1)
}

impl Default for AnalyzerConfig {
    fn default() -> Self {
        Self {
            parallelism: Some(default_parallelism()),
            memo_cache_budget_bytes: Some(256 * 1024 * 1024),
            dispatch_hierarchy_expansion: DispatchHierarchyExpansion::from_environment(),
            rust: RustAnalyzerConfig::default(),
            jvm: JvmAnalyzerConfig::default(),
            csharp: CSharpAnalyzerConfig::default(),
            js_ts: JsTsAnalyzerConfig::default(),
            go: GoAnalyzerConfig::default(),
            python: PythonAnalyzerConfig::default(),
            ruby: RubyAnalyzerConfig::default(),
            php: PhpAnalyzerConfig::default(),
        }
    }
}

impl AnalyzerConfig {
    pub fn parallelism(&self) -> usize {
        self.parallelism.unwrap_or_else(default_parallelism)
    }

    pub fn memo_cache_budget_bytes(&self) -> u64 {
        self.memo_cache_budget_bytes.unwrap_or(256 * 1024 * 1024)
    }
}
