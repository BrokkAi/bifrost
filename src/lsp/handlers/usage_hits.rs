use crate::analyzer::usages::{
    DEFAULT_MAX_FILES, DEFAULT_MAX_USAGES, ExplicitCandidateProvider, UsageFinder, UsageHit,
};
use crate::analyzer::{CodeUnit, IAnalyzer, ProjectFile};
use crate::hash::HashSet;
use std::sync::Arc;

pub(super) fn usage_hits_for_candidates(
    analyzer: &dyn IAnalyzer,
    candidates: &[CodeUnit],
) -> Vec<UsageHit> {
    UsageFinder::new()
        .find_usages(analyzer, candidates, DEFAULT_MAX_FILES, DEFAULT_MAX_USAGES)
        .all_hits()
        .into_iter()
        .collect()
}

pub(super) fn usage_hits_for_candidates_in_file(
    analyzer: &dyn IAnalyzer,
    candidates: &[CodeUnit],
    file: &ProjectFile,
) -> Vec<UsageHit> {
    let files: HashSet<ProjectFile> = [file.clone()].into_iter().collect();
    let provider = ExplicitCandidateProvider::new(Arc::new(files));
    UsageFinder::new()
        .query_with_provider(
            analyzer,
            candidates,
            Some(&provider),
            DEFAULT_MAX_FILES,
            DEFAULT_MAX_USAGES,
        )
        .result
        .all_hits()
        .into_iter()
        .filter(|hit| &hit.file == file)
        .collect()
}
