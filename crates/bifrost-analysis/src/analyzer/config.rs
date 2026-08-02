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
