use crate::analyzer::usages::inverted_edges::UsageEdges;
use crate::analyzer::usages::model::FuzzyResult;
use crate::analyzer::usages::outcome::GraphUsageOutcome;
use crate::analyzer::{CodeUnit, IAnalyzer, ProjectFile};
use crate::hash::HashSet;

/// Strategy for resolving usages of one or more overloads within a candidate file set.
pub trait UsageAnalyzer: Send + Sync {
    fn find_usages(
        &self,
        analyzer: &dyn IAnalyzer,
        overloads: &[CodeUnit],
        candidate_files: &HashSet<ProjectFile>,
        max_usages: usize,
    ) -> FuzzyResult;
}

/// Graph-backed usage strategy that can distinguish fallback-safe gaps from terminal failures.
pub(crate) trait GraphUsageAnalyzer: UsageAnalyzer {
    fn find_graph_usages(
        &self,
        analyzer: &dyn IAnalyzer,
        overloads: &[CodeUnit],
        candidate_files: &HashSet<ProjectFile>,
        max_usages: usize,
    ) -> GraphUsageOutcome;
}

/// Per-language resolver for the `scan_usages` (query) path. Borrows the concrete
/// analyzer out of `&dyn IAnalyzer` in [`try_new`](UsageQueryResolver::try_new) and
/// resolves one target's usages within a candidate file set. One impl per graph
/// language, so "both usage paths share one resolver" is a contract, not convention.
///
/// The `'a` borrow is load-bearing: impls hold `&'a ConcreteAnalyzer` from the analyzer
/// passed to `try_new`. Used only as a static bound, never as `dyn`.
pub(crate) trait UsageQueryResolver<'a>: Sized {
    fn try_new(analyzer: &'a dyn IAnalyzer) -> Option<Self>;

    fn find_usages(
        &self,
        analyzer: &dyn IAnalyzer,
        overloads: &[CodeUnit],
        candidate_files: &HashSet<ProjectFile>,
        max_usages: usize,
    ) -> GraphUsageOutcome;
}

/// Per-language resolver for the `usage_graph` (edge) path. Builds the whole
/// `caller -> callee` edge set in one inverted pass over the workspace. Companion to
/// [`UsageQueryResolver`]; same lifetime contract.
pub(crate) trait UsageEdgeResolver<'a>: Sized {
    fn try_new(analyzer: &'a dyn IAnalyzer) -> Option<Self>;

    fn build_edges<F>(
        &self,
        analyzer: &dyn IAnalyzer,
        nodes: &HashSet<String>,
        keep_file: F,
    ) -> UsageEdges
    where
        F: Fn(&ProjectFile) -> bool + Sync;
}

/// Strategy for narrowing the file set fed into a [`UsageAnalyzer`].
///
/// Implementations should favor false positives over false negatives — over-reporting
/// candidates is fine; missing real call sites is not.
pub trait CandidateFileProvider: Send + Sync {
    fn find_candidates(&self, target: &CodeUnit, analyzer: &dyn IAnalyzer) -> HashSet<ProjectFile>;
}
