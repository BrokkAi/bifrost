use std::path::{Path, PathBuf};

pub const DEFAULT_ANALYZER_ANALYSIS_EPOCH: u64 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnalyzerConfig {
    pub parallelism: Option<usize>,
    pub memo_cache_budget_bytes: Option<u64>,
    pub persistence: AnalyzerPersistenceConfig,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnalyzerPersistenceConfig {
    pub enabled: bool,
    pub cache_dir: Option<PathBuf>,
    pub analysis_epoch: u64,
}

impl Default for AnalyzerConfig {
    fn default() -> Self {
        Self {
            parallelism: Some(
                std::thread::available_parallelism()
                    .map(|value| value.get())
                    .unwrap_or(1),
            ),
            memo_cache_budget_bytes: Some(256 * 1024 * 1024),
            persistence: AnalyzerPersistenceConfig::default(),
        }
    }
}

impl Default for AnalyzerPersistenceConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            cache_dir: None,
            analysis_epoch: DEFAULT_ANALYZER_ANALYSIS_EPOCH,
        }
    }
}

impl AnalyzerConfig {
    pub fn parallelism(&self) -> usize {
        self.parallelism.unwrap_or_else(|| {
            std::thread::available_parallelism()
                .map(|value| value.get())
                .unwrap_or(1)
        })
    }

    pub fn memo_cache_budget_bytes(&self) -> u64 {
        self.memo_cache_budget_bytes.unwrap_or(256 * 1024 * 1024)
    }

    pub(crate) fn persistence_cache_dir(&self, project_root: &Path) -> Option<PathBuf> {
        if !self.persistence.enabled {
            return None;
        }

        Some(
            self.persistence
                .cache_dir
                .clone()
                .unwrap_or_else(|| default_persistence_cache_dir(project_root)),
        )
    }
}

fn default_persistence_cache_dir(project_root: &Path) -> PathBuf {
    let cache_root = enclosing_git_root(project_root)
        .unwrap_or_else(|| project_root.to_path_buf())
        .join("target")
        .join("bifrost-analyzer-cache");
    cache_root.join(project_root_cache_key(project_root))
}

fn enclosing_git_root(project_root: &Path) -> Option<PathBuf> {
    for candidate in project_root.ancestors() {
        if candidate.join(".git").exists() {
            return Some(candidate.to_path_buf());
        }
    }
    None
}

fn project_root_cache_key(project_root: &Path) -> String {
    format!(
        "{:016x}",
        stable_hash(project_root.to_string_lossy().as_bytes())
    )
}

fn stable_hash(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf29ce484222325u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}
