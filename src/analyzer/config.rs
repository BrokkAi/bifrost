#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnalyzerConfig {
    pub parallelism: Option<usize>,
    pub memo_cache_budget_bytes: Option<u64>,
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
