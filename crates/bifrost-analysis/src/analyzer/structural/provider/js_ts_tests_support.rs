use super::*;

#[doc(hidden)]
pub fn assert_limited_source_and_syntax_unavailable(
    provider: &dyn StructuralFactProvider,
    file: &ProjectFile,
    max_source_bytes: usize,
) {
    assert!(matches!(
        provider.structural_source_limited(file, max_source_bytes, None),
        StructuralSourceLimitedOutcome::Unavailable
    ));
    assert!(matches!(
        provider.structural_syntax_limited(file, max_source_bytes, None),
        StructuralSyntaxLimitedOutcome::Unavailable
    ));
}
