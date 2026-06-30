use crate::analyzer::usages::{DEFAULT_MAX_FILES, DEFAULT_MAX_USAGES, UsageFinder, UsageHit};
use crate::analyzer::{CodeUnit, IAnalyzer, ProjectFile};

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
    let scoped_file = file.clone();
    UsageFinder::new()
        .with_file_filter(move |candidate_file| candidate_file == &scoped_file)
        .find_usages(analyzer, candidates, DEFAULT_MAX_FILES, DEFAULT_MAX_USAGES)
        .all_hits()
        .into_iter()
        .filter(|hit| &hit.file == file)
        .collect()
}
