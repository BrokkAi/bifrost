use std::path::PathBuf;
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnalyzerConfig {
    pub parallelism: Option<usize>,
    pub memo_cache_budget_bytes: Option<u64>,
    pub java: JavaAnalyzerConfig,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct JavaAnalyzerConfig {
    pub external_dependencies: JavaExternalDependencies,
    pub dependency_discovery: JavaDependencyDiscoveryConfig,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct JavaExternalDependencies {
    pub artifact_paths: Vec<JavaExternalArtifact>,
    pub coordinates: Vec<JavaMavenCoordinate>,
    pub repository_roots: Vec<PathBuf>,
    pub gradle_cache_roots: Vec<PathBuf>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum JavaDependencyDiscoveryMode {
    Disabled,
    #[default]
    Metadata,
    OfflineBuildTools,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JavaDependencyDiscoveryConfig {
    pub mode: JavaDependencyDiscoveryMode,
    pub maven_executable: Option<PathBuf>,
    pub gradle_executable: Option<PathBuf>,
    pub timeout: Duration,
}

impl Default for JavaDependencyDiscoveryConfig {
    fn default() -> Self {
        Self {
            mode: JavaDependencyDiscoveryMode::Metadata,
            maven_executable: None,
            gradle_executable: None,
            timeout: Duration::from_secs(30),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JavaExternalArtifact {
    pub artifact_path: PathBuf,
    pub source_artifact_path: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct JavaMavenCoordinate {
    pub group_id: String,
    pub artifact_id: String,
    pub version: String,
}

impl JavaMavenCoordinate {
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
            java: JavaAnalyzerConfig::default(),
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
