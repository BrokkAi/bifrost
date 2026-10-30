use super::*;
#[doc(hidden)]
pub fn write_fixture(root: &std::path::Path, files: &[(&str, &str)]) {
    crate::test_support::write_fixture_files(root, files);
}

#[doc(hidden)]
pub fn augmentation_of(
    analyzer: &dyn IAnalyzer,
    target: &CodeUnit,
) -> crate::analyzer::languages::CandidateAugmentation {
    candidate_augmentation(&CandidateCtx {
        analyzer,
        target,
        cancellation: &CancellationToken::default(),
    })
    .expect("fixture target's language augments its candidates")
}

#[doc(hidden)]
pub fn default_route_candidates(
    analyzer: &dyn IAnalyzer,
    target: &CodeUnit,
) -> HashSet<ProjectFile> {
    let uncancelled = CancellationToken::default();
    find_default_candidates_within(
        target,
        analyzer,
        &DescendantIndexScope::whole_workspace(&uncancelled),
    )
}
