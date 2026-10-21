use super::*;

#[doc(hidden)]
pub fn call_span(source: &str, call: &str) -> Range {
    crate::analyzer::usages::test_support::byte_range(source, call)
}

#[doc(hidden)]
pub fn generous_limits() -> CallRelationLimits {
    CallRelationLimits {
        max_files: 1,
        max_source_bytes: usize::MAX,
        max_candidates: 100,
    }
}
