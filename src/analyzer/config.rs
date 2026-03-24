#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnalyzerConfig {
    pub parallelism: Option<usize>,
    pub memo_cache_budget_bytes: Option<u64>,
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
}
