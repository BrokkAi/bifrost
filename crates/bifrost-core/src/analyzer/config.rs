use std::path::PathBuf;
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnalyzerConfig {
    pub parallelism: Option<usize>,
    pub memo_cache_budget_bytes: Option<u64>,
    pub rust: RustAnalyzerConfig,
    pub jvm: JvmAnalyzerConfig,
    pub csharp: CSharpAnalyzerConfig,
    pub js_ts: JsTsAnalyzerConfig,
    pub go: GoAnalyzerConfig,
    pub python: PythonAnalyzerConfig,
    pub ruby: RubyAnalyzerConfig,
    pub php: PhpAnalyzerConfig,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoDependencyDiscoveryConfig {
    /// Go dependency discovery is opt-in because it invokes the configured Go
    /// toolchain and can index a large local module graph.
    pub enabled: bool,
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
            enabled: false,
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

    /// Retained-byte budget for one provider's snapshot structural index.
    /// Sized so a mid-size single-language workspace fits: the Bifrost
    /// repository's own Rust slice (~1,000 files, ~33 MB source) needs about
    /// 30 MB retained and ~100 MB of construction working set (the build cap
    /// is a small multiple of this budget); at the previous memo/8 share the
    /// build was rejected and every structural query fell back to scanning.
    pub fn structural_index_cache_budget_bytes(&self) -> u64 {
        self.memo_cache_budget_bytes() / 4
    }
}
