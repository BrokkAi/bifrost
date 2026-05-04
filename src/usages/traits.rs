use crate::analyzer::{CodeUnit, IAnalyzer, ProjectFile};
use crate::hash::HashSet;
use crate::usages::model::FuzzyResult;

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

/// Strategy for narrowing the file set fed into a [`UsageAnalyzer`].
///
/// Implementations should favor false positives over false negatives — over-reporting
/// candidates is fine; missing real call sites is not.
pub trait CandidateFileProvider: Send + Sync {
    fn find_candidates(
        &self,
        target: &CodeUnit,
        analyzer: &dyn IAnalyzer,
    ) -> HashSet<ProjectFile>;
}
